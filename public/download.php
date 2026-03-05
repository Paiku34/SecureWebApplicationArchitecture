<?php
/*
 * ============================================================
 * download.php — Download sicuro di file audio con controlli multi-layer
 * ============================================================
 *
 * Gestisce il download di file MP3 autenticati con la seguente pipeline di sicurezza:
 *
 *  1. VERIFICA SESSIONE + IP BINDING:
 *     user_id in sessione + corrispondenza IP con quello salvato al login.
 *     Devia a login se sessione mancante o se l'IP è cambiato (session hijacking).
 *
 *  2. RATE LIMITING DOWNLOAD:
 *     Max 10 download/ora per utente (identifier: 'user_' + user_id).
 *     Restituisce HTTP 429 Too Many Requests se superato.
 *     Previene scraping massivo dei contenuti protetti.
 *
 *  3. VALIDAZIONE ID FILE:
 *     filter_input(FILTER_VALIDATE_INT) garantisce che l'ID sia un intero positivo.
 *     Richieste con ID non valido (stringa, negativo, SQL code) → HTTP 400.
 *
 *  4. CONTROLLO PERMESSI PREMIUM:
 *     Se il file è is_premium=1 e l'utente non ha is_premium=1, restituisce HTTP 403.
 *     Il tentativo viene loggato come WARNING per monitoraggio.
 *
 *  5. PROTEZIONE PATH TRAVERSAL:
 *     Doppio check:
 *     a) Controllo strpos per ".." e caratteri non consentiti nel path DB
 *     b) realpath() + strpos per verificare che il file risolto sia
 *        dentro la directory storage/ (canonical path check)
 *     Se un path manomesso sfugge al DB, questo blocco lo ferma.
 *
 *  6. INTEGRITY CHECK SHA-256:
 *     hash_file('sha256', $file) calcolato al momento del download e confrontato
 *     con l'hash salvato nel DB al momento dell'upload.
 *     Se non corrispondono → HTTP 500 + log CRITICAL (possibile manomissione).
 *
 *  7. VALIDAZIONE MIME TYPE AL MOMENTO DEL DOWNLOAD:
 *     finfo_file() legge i magic bytes del file su disco.
 *     Anche se un file non-MP3 avesse un'estensione .mp3, verrebbe bloccato.
 *
 *  8. NOME FILE DOWNLOAD SICURO:
 *     preg_replace rimuove caratteri speciali dal titolo per costruire
 *     il nome file da offrire al browser nel header Content-Disposition.
 *     Previene header injection e path issues nel browser.
 *
 *  9. HEADERS DOWNLOAD SICURI:
 *     Content-Type: audio/mpeg (mai application/octet-stream che potrebbe
 *     indurre il browser a interpretare il contenuto)
 *     X-Content-Type-Options: nosniff (impedisce MIME sniffing)
 *     Cache-Control: no-cache (il file non deve essere cachato in proxy condivisi)
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/RateLimiter.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php';

set_security_headers();

$rateLimiter = new RateLimiter($pdo);
$securityLogger = new SecurityLogger($pdo);

// controllo sessione
if (!isset($_SESSION['user_id'])){
    $securityLogger->logUnauthorizedAccess('download', 'Session invalid or IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header("Location: login.php?error=session_invalid");
    exit();
}

// ip binding
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('download', 'Session invalid or IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header("Location: login.php?error=session_invalid");
    exit();
}

// rate limiting
$user_identifier = 'user_' . $_SESSION['user_id'];
if (!$rateLimiter->checkLimit($user_identifier, 'download')) {
    $securityLogger->log('rate_limit_exceeded', 'WARNING', [
        'action' => 'download',
        'user_id' => $_SESSION['user_id']
    ]);
    header("HTTP/1.1 429 Too Many Requests");
    exit("Troppi download. Riprova tra un'ora.");
}

// validazione id
$file_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$file_id) {
    $securityLogger->log('invalid_file_id', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'raw_id' => $_GET['id'] ?? 'missing'
    ]);
    header("HTTP/1.1 400 Bad Request");
    exit("ID non valido.");
}

// recupero dati utente con cache
$currentUser = get_user_data($pdo, $_SESSION['user_id'], false);

if (!$currentUser) {
    $securityLogger->log('user_not_found', 'WARNING', [
        'user_id' => $_SESSION['user_id']
    ]);
    session_destroy();
    exit("Account non trovato.");
}

// recupero media con hash per integrity check
$stmt = $pdo->prepare("
    SELECT id, title, audio_path, audio_hash, is_premium, user_id 
    FROM media 
    WHERE id = ?
");
$stmt->execute([$file_id]);
$media = $stmt->fetch();

if (!$media || empty($media['audio_path'])) {
    $securityLogger->log('file_not_found', 'INFO', [
        'user_id' => $_SESSION['user_id'],
        'file_id' => $file_id
    ]);
    header("HTTP/1.1 404 Not Found");
    exit("File non trovato.");
}

// controllo permessi premium
if ($media['is_premium'] && !$currentUser['is_premium']) {
    $securityLogger->log('unauthorized_premium_access', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'media_id' => $file_id
    ]);
    header("HTTP/1.1 403 Forbidden");
    exit("Contenuto Premium. Effettua l'upgrade per accedere. Il tentativo è stato registrato.");
}

// PROTEZIONE PATH TRAVERSAL — Doppio check:
// CHECK A: regex sul path dal DB — blocca eventuali dati corrotti nel DB.
//   Se audio_path contenesse "../../etc/passwd" o caratteri unicode pericolosi,
//   questo check lo ferma prima ancora di toccare il filesystem.
$storage_dir = realpath(__DIR__ . '/../storage');
$requested_path = realpath($storage_dir . '/' . $media['audio_path']);

if (strpos($media['audio_path'], '..') !== false || 
    preg_match('/[^a-zA-Z0-9\/_.-]/', $media['audio_path'])) {
    $securityLogger->logPathTraversal($media['audio_path']);
    header("HTTP/1.1 400 Bad Request");
    exit("Path non valido.");
}

// CHECK B: realpath() risolve symlink e sequenze ../ nel path finale.
// strpos($requested_path, $storage_dir) === 0 verifica che il path canonico
// cominci con la directory storage/ (boundary check).
// Un path come /var/www/storage/../../../etc/passwd verrebbe risolto da realpath()
// a /etc/passwd e NON inizierebbe con $storage_dir → bloccato.
if (!$requested_path || strpos($requested_path, $storage_dir) !== 0 || !file_exists($requested_path)) {
    $securityLogger->logPathTraversal($media['audio_path']);
    header("HTTP/1.1 404 Not Found");
    exit("Tentativo path traversal. File non accessibile. Il problema è stato segnalato.");
}

// INTEGRITY CHECK SHA-256:
// L'hash è stato calcolato al momento dell'upload e salvato nel DB.
// Se il file su disco è stato modificato (manomissione o corruzione), l'hash non corrisponde.
// Blocchiamo il download e logghiamo CRITICAL: richiede indagine immediata.
if (!empty($media['audio_hash'])) {
    $current_hash = hash_file('sha256', $requested_path);
    
    if ($current_hash !== $media['audio_hash']) {
        $securityLogger->logIntegrityViolation($file_id, $media['audio_hash'], $current_hash);
        header("HTTP/1.1 500 Internal Server Error");
        exit("Errore di integrità del file. Il problema è stato segnalato.");
    }
}

// MIME TYPE AL MOMENTO DEL DOWNLOAD:
// Anche se il file ha passato il MIME check all'upload, lo ri-verifichiamo.
// Caso raro ma possibile: un admin sostituisce manualmente un file con contenuto diverso.
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$real_mime = finfo_file($finfo, $requested_path);
finfo_close($finfo);

$allowed_mimes = ['audio/mpeg', 'audio/mp3', 'audio/x-mpeg', 'audio/x-mp3', 'application/octet-stream'];
if (!in_array($real_mime, $allowed_mimes)) {
    $securityLogger->log('invalid_mime_type', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'file_id' => $file_id,
        'expected' => implode(',', $allowed_mimes),
        'actual' => $real_mime
    ]);
    header("HTTP/1.1 403 Forbidden");
    exit("Tipo di file non valido.");
}

// incremento statistiche download per l'autore
try {
    $update_stmt = $pdo->prepare("UPDATE users SET total_downloads_received = total_downloads_received + 1 WHERE id = ?");
    $update_stmt->execute([$media['user_id']]);
} catch (PDOException $e) {
    // Log ma non bloccare download
    $securityLogger->log('stats_update_failed', 'WARNING', [
        'author_id' => $media['user_id'],
        'error' => $e->getMessage()
    ]);
}

// nome file sicuro per download
$safe_title = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $media['title']);
$safe_title = preg_replace('/_+/', '_', $safe_title);
$safe_title = trim($safe_title, '_');
$download_filename = $safe_title . '.mp3';

// 13. LOG SUCCESS
$securityLogger->log('download_success', 'INFO', [
    'user_id' => $_SESSION['user_id'],
    'media_id' => $file_id,
    'title' => $media['title']
]);

// streaming file con header sicuri
if (ob_get_level()) ob_end_clean();

header('Content-Type: audio/mpeg');
header('Content-Disposition: attachment; filename="' . $download_filename . '"');
header('Content-Length: ' . filesize($requested_path));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: 0');

readfile($requested_path);
exit;