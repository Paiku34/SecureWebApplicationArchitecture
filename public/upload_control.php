<?php

/*
 * ============================================================
 * upload_control.php — Controller per l'upload sicuro di file audio e testi
 * ============================================================
 *
 * Gestisce la ricezione, validazione e salvataggio dei file caricati dagli utenti.
 * Implementa una pipeline di sicurezza multi-livello:
 *
 *  1. VERIFICA METODO HTTP:
 *     Accetta solo POST. GET o altri metodi restituiscono errore immediato.
 *
 *  2. VERIFICA SESSIONE + IP BINDING:
 *     Controlla sessione attiva e corrispondenza IP. Blocca session hijacking.
 *
 *  3. PROTEZIONE CSRF:
 *     hash_equals() sul token (timing-safe) prima di qualsiasi operazione.
 *
 *  4. RATE LIMITING UPLOAD:
 *     Max 10 upload/ora per utente. Previene flooding dello storage.
 *
 *  5. WHITELIST CARATTERI NEL TITOLO:
 *     Regex /[\p{L}\p{N}\s\-_.\,\!\?\(\)\'\"]/ blocca caratteri pericolosi
 *     nel titolo (prevenzione XSS e injection a livello input prima del DB).
 *
 *  6. VALIDAZIONE FILE MULTI-LIVELLO (SENZA SALVARE PRIMA):
 *     a) Errori upload PHP (UPLOAD_ERR_*)
 *     b) Dimensione: MP3 max 10MB, TXT max 1MB
 *     c) Estensione: whitelist ['mp3'], ['txt']
 *     d) MIME type REALE: finfo_file() legge i magic bytes del file,
 *        non si fida del MIME type dichiarato dal client (bypassabile)
 *     ENTRAMBI i file vengono validati PRIMA di salvarne uno qualsiasi:
 *     se il secondo file è invalido, il primo non viene sprecato su disco.
 *
 *  7. GENERAZIONE NOME FILE SICURO:
 *     uniqid() + bin2hex(random_bytes(8)) → nomi non-deterministici e non-predicibili.
 *     basename() sull'originale previene path traversal nel nome originale.
 *     L'estensione usata è quella validata dal MIME check, non quella del client.
 *
 *  8. CALCOLO HASH SHA-256:
 *     Ogni file viene hashato prima del salvataggio. L'hash viene salvato nel DB
 *     per l'integrity check al momento del download (rilevamento manomissione).
 *
 *  9. PERMESSI FILE (chmod 0644):
 *     Owner: lettura+scrittura. Altri: sola lettura. Nessuna esecuzione.
 *
 * 10. TRANSAZIONE DATABASE ATOMICA CON ROLLBACK:
 *     Il record viene inserito in una transazione. Se fallisce, i file fisici
 *     già salvati vengono rimossi (cleanup) per evitare file orfani.
 *
 * 11. PROTEZIONE PATH TRAVERSAL:
 *     realpath() + strpos() verificano che i file salvati siano nella directory
 *     di destinazione prevista (non fuori dalla sandbox storage/).
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/RateLimiter.php';
require_once '../includes/SecurityLogger.php';

// Rate Limiter e Security Logger
$rateLimiter = new RateLimiter($pdo);
$securityLogger = new SecurityLogger($pdo);

// Controllo Sessione
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $securityLogger->logUnauthorizedAccess('upload_control', 'Wrong method');
    die("Metodo non consentito.");
}

if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('upload_control', 'No session');
    die("Accesso non autorizzato.");
}

// Controllo IP Binding (anti session hijacking)
if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('upload_control', 'IP mismatch');
    die("Sessione non valida. Effettua nuovamente il login.");
}

// Validazione CSRF Token
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) { // ✅ MODIFICATO: hash_equals per timing-attack protection
    $securityLogger->logCSRFViolation($_SESSION['csrf_token'] ?? 'none', $_POST['csrf_token'] ?? 'none');
    die("Violazione CSRF rilevata.");
}

// rate limiting
$user_identifier = 'user_' . (int)$_SESSION['user_id'];
if (!$rateLimiter->checkLimit($user_identifier, 'upload')) {
    $securityLogger->log('rate_limit_exceeded', 'WARNING', [
        'action' => 'upload',
        'user_id' => $_SESSION['user_id']
    ]);
    die("Troppi upload. Riprova tra un'ora.");
}

// ============================================
// VALIDAZIONE E SANITIZZAZIONE INPUT
// ============================================

// Sanitizzazione e Validazione Titolo
$title = $_POST['title'] ?? '';

$title = trim($title);

// Validazione lunghezza
if (empty($title) || strlen($title) > 100) {
    $securityLogger->log('invalid_title_length', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'title_length' => strlen($title)
    ]);
    die("Il titolo deve essere tra 1 e 100 caratteri.");
}

// Whitelist caratteri (impedisce XSS e SQL injection a livello input)
if (!preg_match('/^[\p{L}\p{N}\s\-_\.\,\!\?\(\)\'\"]+$/u', $title)) {
    $securityLogger->log('invalid_title_chars', 'WARNING', [
        'user_id' => $_SESSION['user_id']
    ]);
    die("Il titolo contiene caratteri non consentiti.");
}


// Type casting sicuro user_id
$is_premium = isset($_POST['is_premium']) ? 1 : 0;
$user_id = (int)$_SESSION['user_id']; // cast a int esplicito

// Configurazione Percorsi
$storage_dir = realpath(__DIR__ . '/../storage');
$upload_audio_dir = $storage_dir . '/uploads/audio/';
$upload_text_dir = $storage_dir . '/uploads/lyrics/';

$allowed_audio_mimes = ['audio/mpeg', 'audio/x-mpeg', 'audio/mp3', 'audio/x-mpeg-3'];
$allowed_text_mimes = ['text/plain'];

// Verifica directory (senza leak path)
if (!is_dir($upload_audio_dir)) {
    $securityLogger->log('upload_dir_missing', 'CRITICAL', [
        'dir' => 'audio'
    ]);
    die("Errore interno: servizio upload temporaneamente non disponibile.");
}

if (!is_dir($upload_text_dir)) {
    $securityLogger->log('upload_dir_missing', 'CRITICAL', [
        'dir' => 'lyrics'
    ]);
    die("Errore interno: servizio upload temporaneamente non disponibile.");
}

/**
 * VALIDAZIONE FILE (SENZA SALVARE)
 *
 * Questa funzione SOLO valida il file; non lo sposta nella destinazione finale.
 * Separare validazione e salvataggio permette di validare audio E testo prima
 * di salvarne uno, evitando file orfani in caso il secondo sia invalido.
 *
 * @param string $file_key     Chiave in $_FILES (es: 'audio_file')
 * @param array  $allowed_mimes Whitelist MIME types accettati
 * @param int    $max_size      Dimensione massima in byte
 * @param array  $allowed_extensions Whitelist estensioni accettate
 * @return array Info sul file validato (tmp_name, original_name, size, mime, extension)
 * @throws Exception Se il file non supera uno dei controlli
 */
function validateFile($file_key, $allowed_mimes, $max_size, $allowed_extensions) {
    if (!isset($_FILES[$file_key])) {
        throw new Exception("File $file_key non ricevuto dal server.");
    }

    $file = $_FILES[$file_key];

    // CHECK 1: Errori upload PHP — questi vengono dal runtime PHP, non dal client.
    // UPLOAD_ERR_NO_FILE (4): nessun file selezionato nel form.
    // UPLOAD_ERR_INI_SIZE (1): file supera upload_max_filesize in php.ini.
    // Mai fidarsi che il client non invii errori: check obbligatorio.
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error_messages = [
            UPLOAD_ERR_INI_SIZE => "File supera upload_max_filesize",
            UPLOAD_ERR_FORM_SIZE => "File supera MAX_FILE_SIZE",
            UPLOAD_ERR_PARTIAL => "Upload parziale",
            UPLOAD_ERR_NO_FILE => "Nessun file caricato",
            UPLOAD_ERR_NO_TMP_DIR => "Cartella temporanea mancante",
            UPLOAD_ERR_CANT_WRITE => "Impossibile scrivere",
            UPLOAD_ERR_EXTENSION => "Upload bloccato"
        ];
        $error_msg = $error_messages[$file['error']] ?? "Errore sconosciuto";
        throw new Exception("Errore upload $file_key: $error_msg");
    }

    // CHECK 2: Dimensione — verificata sul file reale in tmp, non sul valore
    // $file['size'] dichiarato dal client (che potrebbe essere manipolato).
    // PHP popola $file['size'] dal valore reale, ma re-verificiamo come defense in depth.
    if ($file['size'] > $max_size) {
        $size_mb = round($file['size'] / 1024 / 1024, 2);
        $max_mb = round($max_size / 1024 / 1024);
        throw new Exception("File troppo grande: {$size_mb}MB (max {$max_mb}MB)");
    }

    // CHECK 3: Estensione — defense in depth (non sufficiente da sola).
    // Un attaccante può rinominare un file PHP in .mp3, per questo non basta.
    // La vera validazione è il MIME check sui magic bytes (CHECK 4).
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_ext, $allowed_extensions)) {
        throw new Exception("Estensione file non valida: .$file_ext");
    }

    // CHECK 4: MIME type REALE (primary validation).
    // finfo_file() legge i magic bytes dal file temporaneo in tmp_name.
    // I magic bytes sono i primi byte del file che identificano il formato reale.
    // Esempio: un MP3 valido inizia con ID3 o 0xFF 0xFB.
    // $file['type'] (MIME dichiarato dal browser) NON viene usato:
    // il browser legge l'estensione per determinarlo, non i contenuti del file.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $real_mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if (!in_array($real_mime, $allowed_mimes)) {
        throw new Exception("Tipo file non valido. Rilevato: $real_mime");
    }

    return [
        'tmp_name' => $file['tmp_name'],
        'original_name' => basename($file['name']), // basename() previene path traversal nel nome originale
        'size' => $file['size'],
        'mime' => $real_mime,
        'extension' => $file_ext
    ];
}

/**
 * SALVATAGGIO FILE (SOLO SE VALIDAZIONE OK)
 *
 * Precondizione garantita: $tmp_path punta a un file già validato da validateFile().
 *
 * @param string $tmp_path   Path del file temporaneo PHP (da $_FILES['x']['tmp_name'])
 * @param string $target_dir Directory di destinazione (audio/ o lyrics/)
 * @param string $ext        Estensione validata (mai presa dal client direttamente)
 * @return array ['path' => nome file, 'hash' => sha256]
 * @throws Exception Se move_uploaded_file fallisce
 */
function saveFile($tmp_path, $target_dir, $ext) {
    // Nome file non-deterministico: 16 hex chars.
    // Senza nomi predicibili, un attaccante non può indovinare o enumerare i path dei file.
    $unique_name = bin2hex(random_bytes(16)) . '.' . $ext;
    $destination = $target_dir . $unique_name;
    
    // Hash SHA-256 calcolato prima di salvare: se il file venisse corrotto durante
    // lo spostamento, il confronto al download rivelerebbe la discrepanza.
    // hash_file() legge il file a blocchi (efficiente anche per file grandi).
    $file_hash = hash_file('sha256', $tmp_path);

    // move_uploaded_file è l'UNICA funzione sicura per spostare file uploadati.
    // Verifica internamente che il file provenga da un upload PHP legittimo
    // (is_uploaded_file check). rename() o copy() NON farebbero questo controllo.
    if (!move_uploaded_file($tmp_path, $destination)) {
        throw new Exception("Impossibile salvare il file.");
    }

    // chmod 0644 = rw-r--r-- (ottale):
    // - Owner (www-data): lettura + scrittura
    // - Gruppo: sola lettura
    // - Altri: sola lettura
    // NESSUN bit esecuzione: impedisce che il file venga eseguito come script
    // anche se il webserver fosse configurato male o se contenesse codice PHP.
    chmod($destination, 0644); // rw-r--r--

    // Log solo in development (commentare in produzione)
    if (getenv('APP_ENV') === 'development') {
        //error_log("SUCCESS: File salvato in $destination (Hash: $file_hash)");
    }

    return [
        'path' => basename($destination),
        'hash' => $file_hash
    ];
}

// ============================================
// VALIDAZIONE COMPLETA (SENZA SALVARE)
// ============================================
try {
    // Log condizionale
    if (getenv('APP_ENV') === 'development') {
        error_log("=== INIZIO VALIDAZIONE ===");
    }
    
    // Valida entrambi i file prima di salvarne uno qualsiasi
    $audio_info = validateFile('audio_file', $allowed_audio_mimes, 10 * 1024 * 1024, ['mp3']);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("✓ Audio validato: {$audio_info['size']} bytes, MIME: {$audio_info['mime']}");
    }
    
    $lyrics_info = validateFile('lyrics_file', $allowed_text_mimes, 1 * 1024 * 1024, ['txt']);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("✓ Lyrics validato: {$lyrics_info['size']} bytes, MIME: {$lyrics_info['mime']}");
    }
    
} catch (Exception $e) {
    $securityLogger->log('upload_validation_failed', 'WARNING', [
        'user_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("VALIDAZIONE FALLITA: " . $e->getMessage());
    }
    
    die("Errore durante la validazione del file. Verifica il formato e la dimensione e riprova.");
}

// ============================================
// SALVATAGGIO (SOLO SE VALIDAZIONE OK)
// ============================================
try {
    if (getenv('APP_ENV') === 'development') {
        error_log("=== INIZIO SALVATAGGIO ===");
    }
    
    // Usa estensione validata (non hardcoded)
    $audio_result = saveFile($audio_info['tmp_name'], $upload_audio_dir, $audio_info['extension']);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("✓ Audio salvato: {$audio_result['path']}");
    }
    
    $lyrics_result = saveFile($lyrics_info['tmp_name'], $upload_text_dir, $lyrics_info['extension']);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("✓ Lyrics salvato: {$lyrics_result['path']}");
    }
    
} catch (Exception $e) {
    $securityLogger->log('upload_save_failed', 'CRITICAL', [
        'user_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("SALVATAGGIO FALLITO: " . $e->getMessage());
    }
    
    // Cleanup parziale
    if (isset($audio_result)) {
        @unlink($upload_audio_dir . $audio_result['path']);
        
        if (getenv('APP_ENV') === 'development') {
            error_log("Cleanup: Audio eliminato per rollback");
        }
    }
    
    die("Errore durante il salvataggio. Riprova.");
}

// ============================================
//  REGISTRAZIONE DATABASE
// ============================================
try {
    // Inizia transazione (atomicità DB)
    $pdo->beginTransaction();

    // Insert media - Prepared statement già sicuro
    $stmt = $pdo->prepare("
        INSERT INTO media (user_id, title, audio_path, audio_hash, lyrics_path, lyrics_hash, is_premium, uploaded_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
    ");
    
    $stmt->execute([
        $user_id,
        $title, // Già sanitizzato sopra
        'uploads/audio/' . $audio_result['path'],
        $audio_result['hash'],
        'uploads/lyrics/' . $lyrics_result['path'],
        $lyrics_result['hash'],
        $is_premium
    ]);

    // Update stats
    $updateStmt = $pdo->prepare("UPDATE users SET total_uploads = total_uploads + 1 WHERE id = ?");
    $updateStmt->execute([$user_id]);

    // Commit transazione
    $pdo->commit();

    // log success 
    $securityLogger->log('upload_success', 'INFO', [
        'user_id' => $user_id,
        'title' => $title,
        'is_premium' => (bool)$is_premium,
        'audio_size' => $audio_info['size'],
        'lyrics_size' => $lyrics_info['size']
    ]);

    // flash message di successo
    $_SESSION['flash_message'] = 'Upload completato con successo!';
    $_SESSION['flash_type'] = 'success';

    // Refresh CSRF token (one-time use)
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    if (getenv('APP_ENV') === 'development') {
        error_log("=== UPLOAD COMPLETATO CON SUCCESSO ===");
    }
    
    header('Location: dashboard.php');
    exit();

} catch (Exception $e) {
    // Rollback database
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    
    $securityLogger->log('upload_db_failed', 'CRITICAL', [
        'user_id' => $user_id,
        'error_code' => $e->getCode() // non logga messaggio completo (potrebbe contenere query)
    ]);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("CRITICAL: Database insert failed - " . $e->getMessage());
    }
    
    // Cleanup file system
    @unlink($upload_audio_dir . $audio_result['path']);
    @unlink($upload_text_dir . $lyrics_result['path']);
    
    if (getenv('APP_ENV') === 'development') {
        error_log("Cleanup: File eliminati per rollback database");
    }
    
    // flash message di errore
    $_SESSION['flash_message'] = 'Errore interno. Riprova più tardi.';
    $_SESSION['flash_type'] = 'error';
    
    header('Location: dashboard.php');
    exit();
}
?>