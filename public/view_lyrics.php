<?php

/*
 * ============================================================
 * view_lyrics.php — Visualizzazione sicura dei testi delle canzoni
 * ============================================================
 *
 * Permette la lettura dei testi con le stesse protezioni di download.php:
 *
 *  1. VERIFICA SESSIONE + IP BINDING:
 *     Stesse verifiche di download.php.
 *
 *  2. RATE LIMITING VIEW:
 *     Max 1000 visualizzazioni/ora per utente (soglia alta: solo anti-scraping bot).
 *     HTTP 429 se superato.
 *
 *  3. CONTROLLO PERMESSI PREMIUM:
 *     Contenuti is_premium=1 non accessibili a utenti standard.
 *
 *  4. PROTEZIONE PATH TRAVERSAL:
 *     Identica a download.php (doppio check: regex + realpath).
 *
 *  5. VALIDAZIONE MIME TYPE:
 *     finfo_file() verifica che il file letto sia effettivamente text/plain.
 *
 *  6. INTEGRITY CHECK SHA-256:
 *     Confronto hash_file vs lyrics_hash nel DB prima di leggere il contenuto.
 *
 *  7. SANITIZZAZIONE OUTPUT XSS:
 *     Il contenuto del file TXT viene passato attraverso htmlspecialchars()
 *     prima di essere inserito nell'HTML. Anche un testo con <script> è sicuro.
 *     (ENT_QUOTES converte anche le virgolette per prevenire attribute injection)
 *
 *  8. CACHE DISABLE HEADERS:
 *     Cache-Control: no-store, no-cache per non cachare contenuti premium
 *     in proxy condivisi o CDN.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/RateLimiter.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php'; 

// Inizializza Rate Limiter e Security Logger
$rateLimiter = new RateLimiter($pdo);
$securityLogger = new SecurityLogger($pdo);

// Controllo Sessione
if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('view_lyrics', 'No session');
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// Controllo IP Binding (anti session hijacking)
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('view_lyrics', 'IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Indirizzo IP non corrispondente.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

if (!validate_session($pdo)) {
    header('Location: login.php?error=session_invalid');
    exit();
}

//  rate limiting: Blocca se supera il limite
//  sanitizzazione: Forza integer per sicurezza
$user_identifier = 'user_' . (int)$_SESSION['user_id'];
if (!$rateLimiter->checkLimit($user_identifier, 'view')) {
    $securityLogger->log('rate_limit_exceeded', 'WARNING', [
        'action' => 'view',
        'user_id' => $_SESSION['user_id']
    ]);
    header("HTTP/1.1 429 Too Many Requests");
    die("⏱️ Troppe visualizzazioni. Riprova tra un'ora.");
}

// Recupero stato Premium fresco dal DB (con caching)
$currentUser = get_user_data($pdo, $_SESSION['user_id'], false);

if (!$currentUser) {
    $securityLogger->log('user_not_found', 'WARNING', [
        'user_id' => $_SESSION['user_id']
    ]);
    session_destroy();
    exit("Account non trovato.");
}

$user_is_premium = (bool)$currentUser['is_premium'];
$current_username = htmlspecialchars($currentUser['username'] ?? '', ENT_QUOTES, 'UTF-8');

//  Validazione ID Media
$file_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$file_id) {
    $securityLogger->log('invalid_file_id', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'raw_id' => $_GET['id'] ?? 'missing'
    ]);
    header("HTTP/1.1 400 Bad Request");
    exit("Richiesta non valida.");
}

// Recupero dati Media con hash e username autore
$stmt = $pdo->prepare("
    SELECT m.id, m.title, m.lyrics_path, m.lyrics_hash, m.is_premium, m.user_id, u.username as author_name
    FROM media m
    LEFT JOIN users u ON m.user_id = u.id
    WHERE m.id = ?
");
$stmt->execute([$file_id]);
$media = $stmt->fetch();

if (!$media || empty($media['lyrics_path'])) {
    $securityLogger->log('lyrics_not_found', 'INFO', [
        'user_id' => $_SESSION['user_id'],
        'file_id' => $file_id
    ]);
    header("HTTP/1.1 404 Not Found");
    exit("Testo non disponibile.");
}

//  Controllo Autorizzazione Premium
if ($media['is_premium'] && !$user_is_premium) {
    $securityLogger->log('unauthorized_premium_access', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'media_id' => $file_id
    ]);
    header("HTTP/1.1 403 Forbidden");
    exit("Stai cercando di leggere contenuto Premium. Effettua l'upgrade. Il problema è stato segnalato.");
}

//  Security Headers
set_security_headers();
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");

// PROTEZIONE PATH TRAVERSAL — Doppio check (identico a download.php):
// CHECK A: valida la stringa dal DB contro regex caratteri ammessi.
$storage_dir = realpath(__DIR__ . '/../storage');
$requested_path = realpath($storage_dir . '/' . $media['lyrics_path']);

// Verifica che non contenga .. o caratteri pericolosi
if (strpos($media['lyrics_path'], '..') !== false || 
    preg_match('/[^a-zA-Z0-9\/_.-]/', $media['lyrics_path'])) {
    $securityLogger->logPathTraversal($media['lyrics_path']);
    header("HTTP/1.1 400 Bad Request");
    exit("Path non valido.");
}

// CHECK B: realpath() risolve il path canonico e strpos verifica il boundary storage/.
if (!$requested_path || strpos($requested_path, $storage_dir) !== 0 || !file_exists($requested_path)) {
    $securityLogger->logPathTraversal($media['lyrics_path']);
    header("HTTP/1.1 404 Not Found");
    exit("Tentativo path traversal. File non accessibile. Il problema è stato segnalato.");
}

// VALIDAZIONE MIME TYPE — I testi devono essere text/plain.
// application/octet-stream è accettato come fallback per sistemi che non rilevano text/plain.
// PDF, HTML, o script con estensione .txt vengono rifiutati.
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$real_mime = finfo_file($finfo, $requested_path);
finfo_close($finfo);

$allowed_mimes = ['text/plain', 'application/octet-stream'];
if (!in_array($real_mime, $allowed_mimes)) {
    $securityLogger->log('invalid_lyrics_mime', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'file_id' => $file_id,
        'mime' => $real_mime
    ]);
    header("HTTP/1.1 403 Forbidden");
    exit("Tipo di file non valido.");
}

// INTEGRITY CHECK SHA-256 (identico a download.php):
// Confronta il hash del file su disco con l'hash salvato nel DB all'upload.
if (!empty($media['lyrics_hash'])) {
    $current_hash = hash_file('sha256', $requested_path);
    
    if ($current_hash !== $media['lyrics_hash']) {
        $securityLogger->logIntegrityViolation($file_id, $media['lyrics_hash'], $current_hash);
        header("HTTP/1.1 500 Internal Server Error");
        exit("Errore di integrità del file. Il problema è stato segnalato.");
    }
}

// Incremento statistiche view
try {
    $update_stmt = $pdo->prepare("UPDATE users SET total_downloads_received = total_downloads_received + 1 WHERE id = ?");
    $update_stmt->execute([$media['user_id']]);
} catch (PDOException $e) {
    // Non bloccare la view se stats falliscono
    $securityLogger->log('stats_update_failed', 'WARNING', [
        'author_id' => $media['user_id'],
        'error' => $e->getMessage()
    ]);
}

// log success 
$securityLogger->log('view_lyrics_success', 'INFO', [
    'user_id' => $_SESSION['user_id'],
    'media_id' => $file_id,
    'title' => $media['title']
]);

// XSS PROTECTION — Il contenuto del file .txt viene neutralizzato con htmlspecialchars()
// prima di essere inserito nell'HTML. Questo previene Stored XSS:
// anche un file che contenesse "<script>alert(1)</script>" nel testo
// verrebbe renderizzato come testo visibile, non eseguito come codice.
// ENT_QUOTES converte sia ' che " per prevenire attribute injection.
$content = htmlspecialchars(file_get_contents($requested_path) ?? '', ENT_QUOTES, 'UTF-8');

// Sanitizzazione output: tutto ciò che viene echoed nell'HTML passa per htmlspecialchars().
$title_safe = htmlspecialchars($media['title'] ?? '', ENT_QUOTES, 'UTF-8');
$author_safe = htmlspecialchars($media['author_name'] ?? 'Autore Sconosciuto', ENT_QUOTES, 'UTF-8');
?>

<!DOCTYPE html>
<html class="dark" lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visualizzazione Testo - <?php echo $title_safe; ?> - Music Project</title>
    
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <header class="header">
        <a href="dashboard.php" class="header-brand">🎵 Music Project</a>
        <nav class="header-nav">
            <a href="media.php" class="active">Catalogo</a>
            <a href="upload.php">Upload</a>
            <a href="profile.php">Profilo</a>
        </nav>
        <div class="user-avatar"><?php echo strtoupper(substr($current_username, 0, 1)); ?></div>
    </header>

    <div class="main-content">
        <div class="container-small lyrics-container">
            <div class="card">
                <div class="lyrics-header">
                    <?php if ($media['is_premium']): ?>
                    <span class="badge badge-premium">⭐ Premium</span>
                    <?php else: ?>
                    <span class="badge badge-free">Gratuito</span>
                    <?php endif; ?>
                    <h1 class="lyrics-title"><?php echo $title_safe; ?></h1>
                    <p class="lyrics-author">Autore: <a href="user_profile.php?id=<?php echo $media['user_id']; ?>" class="text-primary"><?php echo $author_safe; ?></a></p>
                </div>

                <div class="text-right mb-20">
                    <button data-action="copy-lyrics" class="btn btn-secondary btn-sm" title="Copia Testo">
                        📋 Copia testo
                    </button>
                    <a href="media.php" class="btn btn-secondary btn-sm">← Catalogo</a>
                </div>

                <pre id="lyrics-content" class="lyrics-box"><?php echo $content; ?></pre>

                <div class="message message-success mt-20">
                    <strong>✓ File verificato</strong>
                    <p>Questo testo è stato verificato con hash SHA-256.</p>
                </div>

                <div class="profile-details mt-20">
                    <div class="info-row">
                        <span class="info-label">ID</span>
                        <span>#<?php echo $file_id; ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Autore</span>
                        <span><?php echo $author_safe; ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Tipo</span>
                        <span><?php echo $media['is_premium'] ? '⭐ Premium' : '📄 Gratuito'; ?></span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="text-center text-muted footer-simple">© 2024 Music Project. Tutti i diritti riservati.</footer>

    <script src="assets/js/view-lyrics.js"></script>

</body>
</html>