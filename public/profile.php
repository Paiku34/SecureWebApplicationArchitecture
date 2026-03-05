<?php
/*
 * profile.php - Pagina profilo utente
 * 
 * Mostra dati profilo, statistiche upload/download, stato premium.
 * Controllo sessione, IP binding, mascheramento email.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/RateLimiter.php';

$securityLogger = new SecurityLogger($pdo);
$rateLimiter = new RateLimiter($pdo);

// controllo accesso
if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('user_profile', 'No session');
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// ip binding
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

// validazione input id
$author_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

// Se non è fornito ID o non è valido, mostra il proprio profilo
if ($author_id === false || $author_id === null) {
    $author_id = (int)$_SESSION['user_id'];
}

// recupero dati utente
$stmt = $pdo->prepare("
    SELECT username, email, is_premium, is_admin, total_uploads, total_downloads_received 
    FROM users 
    WHERE id = ?
");
$stmt->execute([$author_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// Verifica che l'utente esista
if (!$user) {
    $securityLogger->log('profile_not_found', 'WARNING', [
        'viewer_id' => $_SESSION['user_id'],
        'requested_id' => $author_id
    ]);
    
    $_SESSION['flash_message'] = 'Profilo non trovato.';
    $_SESSION['flash_type'] = 'error';
    
    header('Location: dashboard.php');
    exit();
}

// log primo accesso sessione
if (!isset($_SESSION['profile_logged'])) {
    $securityLogger->log('profile_access', 'INFO', [
        'viewer_id' => $_SESSION['user_id'],
        'viewed_profile_id' => $author_id,
        'username' => $user['username']
    ]);
    $_SESSION['profile_logged'] = true;
}

set_security_headers();

// mascheramento email per privacy
function maskEmail($email) {
    // Step 1: Validation (blocca input pericolosi)
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return "***@***";
    }
    
    $parts = explode("@", $email);
    if (count($parts) < 2) return "***@***";
    
    $name = $parts[0];
    $domain = $parts[1];
    
    // rimuovi caratteri pericolosi
    $name = preg_replace('/[^a-zA-Z0-9._-]/', '', $name);
    $domain = preg_replace('/[^a-zA-Z0-9.-]/', '', $domain);
    
    if (empty($name) || empty($domain)) {
        return "***@***";
    }
    
    // Masking
    $len = strlen($name);
    if ($len <= 2) {
        $maskedName = substr($name, 0, 1) . "***";
    } else {
        $maskedName = substr($name, 0, 2) . str_repeat('*', 5) . substr($name, -1);
    }
    
    // Final Escape (defense in depth)
    return htmlspecialchars($maskedName . "@" . $domain, ENT_QUOTES, 'UTF-8');
}

$maskedEmail = maskEmail($user['email']);

// escape dati per output
$username_safe = htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8');
$is_premium_safe = (bool)$user['is_premium'];
$is_admin_safe = (bool)$user['is_admin'];
$total_uploads_safe = (int)$user['total_uploads'];
$total_downloads_safe = (int)$user['total_downloads_received'];
?>

<!DOCTYPE html>
<html class="dark" lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Il Mio Profilo - MusicApp</title>
    
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <!-- Header -->
    <header class="header">
        <a href="dashboard.php" class="header-brand">
            🎵 MusicApp
        </a>
        <div class="header-user">
            <a href="dashboard.php" class="btn btn-secondary btn-sm">← Dashboard</a>
            <div class="user-avatar">
                <?php echo strtoupper(substr($username_safe, 0, 1)); ?>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <div class="main-content">
        <div class="container-small">
            
            <!-- Page Header -->
            <div class="card-header">
                <h1 class="card-title">Il Mio Profilo</h1>
                <p class="card-subtitle">Gestisci le tue informazioni e visualizza le tue statistiche</p>
            </div>

            <!-- Profile Card -->
            <div class="card">
                <div class="profile-header">
                    <div class="profile-avatar">
                        <?php echo strtoupper(substr($username_safe, 0, 1)); ?>
                    </div>
                    <div class="profile-info">
                        <h2><?php echo $username_safe; ?></h2>
                        <div class="inline-flex-row-wrap mt-10">
                            <?php if ($is_premium_safe): ?>
                                <span class="badge badge-premium">⭐ Premium</span>
                            <?php else: ?>
                                <span class="badge badge-standard">Standard</span>
                            <?php endif; ?>
                            <?php if ($is_admin_safe): ?>
                                <span class="badge badge-admin">Amministratore</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <!-- Stats -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-value"><?php echo $total_uploads_safe; ?></span>
                        <span class="stat-label">Miei Upload</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value"><?php echo number_format($total_downloads_safe, 0, ',', '.'); ?></span>
                        <span class="stat-label">Download Ricevuti</span>
                    </div>
                </div>

                <!-- Details -->
                <div class="profile-details">
                    <div class="info-row">
                        <span class="info-label">Nome Utente</span>
                        <span><?php echo $username_safe; ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Email</span>
                        <span class="mono-text"><?php echo $maskedEmail; ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Stato Account</span>
                        <span>
                            <?php if ($is_premium_safe): ?>
                                <span class="badge badge-premium">Abbonamento Attivo</span>
                            <?php else: ?>
                                <span class="badge badge-standard">Versione Gratuita</span>
                            <?php endif; ?>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Ruolo</span>
                        <span class="<?php echo $is_admin_safe ? 'text-error' : ''; ?>">
                            <?php echo $is_admin_safe ? 'Amministratore' : 'Autore / Utente'; ?>
                        </span>
                    </div>
                </div>

                <!-- Actions -->
                <div class="text-center mt-30">
                    <a href="change_password.php" class="btn btn-primary">
                        🔑 Cambia Password
                    </a>
                </div>
            </div>

        </div>
    </div>

    <script src="assets/js/profile.js"></script>

</body>
</html>