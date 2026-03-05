<?php

/*
 * user_profile.php - Profilo pubblico autore
 * 
 * Mostra le statistiche pubbliche di un autore (upload, download ricevuti, badge premium).
 * Include controlli di accesso (sessione, IP binding), validazione input,
 * escape output contro XSS, e logging visualizzazioni profilo.
 * Privacy-first: nessun dato sensibile (email) esposto.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/SecurityLogger.php';

// Inizializza SecurityLogger
$securityLogger = new SecurityLogger($pdo);

// controllo accesso: Solo gli utenti loggati possono vedere i profili degli autori
if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('user_profile', 'No session');
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// controllo IP Binding (anti session hijacking)
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('user_profile', 'IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Indirizzo IP non corrispondente.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

if (!validate_session($pdo)) {
    header('Location: login.php?error=session_invalid');
    exit();
}

// validazione input: ID autore deve essere un intero
$author_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if (!$author_id) {
    $securityLogger->log('invalid_author_id', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'raw_id' => $_GET['id'] ?? 'missing'
    ]);
    header("HTTP/1.1 400 Bad Request");
    exit("Richiesta non valida."); 
}

/**
 * recupero dati autore (privacy first)
 * non selezioniamo l'email né altri dati sensibili.
 * prepared statements contro SQL injection.
 */
$stmt = $pdo->prepare("SELECT username, is_premium, total_uploads, total_downloads_received FROM users WHERE id = ?");
$stmt->execute([$author_id]);
$author = $stmt->fetch();

if (!$author) {
    $securityLogger->log('author_not_found', 'INFO', [
        'viewer_id' => $_SESSION['user_id'],
        'author_id' => $author_id
    ]);
    header("HTTP/1.1 404 Not Found");
    exit("Profilo autore inesistente."); 
}

// Logga la visualizzazione del profilo (una tantum per profilo per sessione)
if(!isset($_SESSION['viewed_profiles'][$author_id])) {
    $securityLogger->log('profile_view', 'INFO', [
        'viewer_id' => $_SESSION['user_id'],
        'author_id' => $author_id,
        'author_username' => $author['username']
    ]);
    $_SESSION['viewed_profiles'][$author_id] = true;
}


/**
 * SECURITY HEADERS (Extreme Defense)
 * Impediamo Clickjacking e XSS.
 */
set_security_headers();
header("Cache-Control: no-cache, must-revalidate");

// Pre-escape dati
$username_safe = htmlspecialchars($author['username'] ?? '', ENT_QUOTES, 'UTF-8');
$is_premium_safe = (bool)$author['is_premium'];
$total_uploads_safe = (int)$author['total_uploads'];
$total_downloads_safe = (int)$author['total_downloads_received'];
?>

<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profilo di @<?php echo $username_safe; ?> - MusicApp</title>
    
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <header class="header">
        <a href="dashboard.php" class="header-brand">🎵 MusicApp</a>
        <div class="header-user">
            <a href="media.php" class="btn btn-secondary btn-sm">← Torna al Catalogo</a>
        </div>
    </header>

    <div class="main-content">
        <div class="container-small">
            <div class="card-header">
                <h1 class="card-title">Profilo Autore</h1>
                <p class="card-subtitle">Informazioni pubbliche di @<?php echo $username_safe; ?></p>
            </div>

            <div class="card">
                <div class="profile-header">
                    <div class="profile-avatar"><?php echo strtoupper(substr($username_safe, 0, 1)); ?></div>
                    <div class="profile-info">
                        <h2>@<?php echo $username_safe; ?></h2>
                        <?php if ($is_premium_safe): ?>
                            <span class="badge badge-premium">Autore Premium</span>
                        <?php else: ?>
                            <span class="badge badge-standard">Autore Base</span>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-value"><?php echo $total_uploads_safe; ?></span>
                        <span class="stat-label">Upload Totali</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value"><?php echo number_format($total_downloads_safe, 0, ',', '.'); ?></span>
                        <span class="stat-label">Download Ricevuti</span>
                    </div>
                </div>

                <div class="message message-info">
                    <strong>Informazioni autore</strong>
                    <p>
                        <strong>@<?php echo $username_safe; ?></strong> è un membro attivo della community MusicApp.
                        <?php if ($total_uploads_safe > 10): ?>
                        Con oltre <strong><?php echo $total_uploads_safe; ?></strong> contenuti caricati, dimostra un impegno costante.
                        <?php elseif ($total_uploads_safe > 0): ?>
                        Ha condiviso <strong><?php echo $total_uploads_safe; ?></strong> contenuti con la community.
                        <?php else: ?>
                        Questo autore ha appena iniziato il suo percorso su MusicApp.
                        <?php endif; ?>
                    </p>
                    <?php if ($total_downloads_safe > 100): ?>
                    <p class="text-success mt-10">✓ Autore molto apprezzato dalla community</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

</body>
</html>