<?php
/*
 * dashboard.php - Pagina principale utente autenticato
 * 
 * Mostra cards navigazione (media, upload, profilo, admin).
 * Valida sessione con timeout, IP binding, caching dati utente.
 */
require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php';

// valida sessione con timeout
if (!validate_session($pdo)) {
    header('Location: login.php');
    exit();
}

// ip binding - blocca session hijacking
if (isset($_SESSION['ip_address'])) {
    if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
        $securityLogger = new SecurityLogger($pdo);
        $securityLogger->log('ip_mismatch', 'WARNING', [
            'user_id' => $_SESSION['user_id'],
            'expected_ip' => $_SESSION['ip_address'],
            'actual_ip' => $_SERVER['REMOTE_ADDR']
        ]);
        session_destroy();
        header('Location: login.php?error=ip_mismatch');
        exit();
    }
}

$securityLogger = new SecurityLogger($pdo);

// recupera dati utente con cache
$user = get_user_data($pdo, $_SESSION['user_id'], false);

// esistenza utente
if (!$user) {
    $securityLogger->log('account_not_found', 'WARNING', [
        'user_id' => $_SESSION['user_id']
    ]);
    session_destroy();
    header('Location: login.php?error=account_not_found');
    exit();
}

// utente bannato
if ($user['is_banned'] == 1) {
    $securityLogger->log('banned_user_access_attempt', 'WARNING', [
        'user_id' => $_SESSION['user_id'],
        'username' => $user['username']
    ]);
    session_destroy(); // Distrugge la sessione immediatamente
    header('Location: login.php?error=account_banned'); // Rimanda al login con messaggio specifico
    exit();
}

// saluto dinamico in base all'ora
date_default_timezone_set('Europe/Rome');
$ora = (int)date('H');

if ($ora < 12) {
    $saluto = "Buongiorno";
} elseif ($ora < 18) {
    $saluto = "Buon pomeriggio";
} else {
    $saluto = "Buonasera";
}

// log primo accesso sessione
if (!isset($_SESSION['dashboard_logged'])) {
    $securityLogger->log('dashboard_access', 'INFO', [
        'user_id' => $_SESSION['user_id'],
        'username' => $user['username'],
        'saluto' => $saluto
    ]);
    $_SESSION['dashboard_logged'] = true;
}

// escape dati per output html
$username_safe = htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8');
$saluto_safe = htmlspecialchars($saluto ?? '', ENT_QUOTES, 'UTF-8');

// Ultimo accesso (formattato)
$ultimo_accesso = date('d/m/Y, H:i');

// Security Headers centralizzati
set_security_headers();
?>

<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - MusicProject</title>
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <!-- Header -->
    <header class="header">
        <a href="dashboard.php" class="header-brand">
            🎵 MusicProject
        </a>
        <div class="header-user">
            <a href="logout.php" class="btn btn-secondary btn-sm">Logout</a>
            <div class="user-avatar">
                <?php echo strtoupper(substr($username_safe, 0, 1)); ?>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <div class="main-content">
        <div class="container">
            
            <!-- Welcome Header -->
            <div class="card-header">
                <h1 class="card-title">
                    <?php echo $saluto_safe; ?>, <?php echo $username_safe; ?>
                </h1>
                <div>
                    <?php if ($user['is_premium']): ?>
                        <span class="badge badge-premium">⭐ Account Premium</span>
                    <?php else: ?>
                        <span class="badge badge-standard">Account Standard</span>
                    <?php endif; ?>
                    <span class="text-muted ml-15">
                        Ultimo accesso: Oggi, <?php echo date('H:i'); ?>
                    </span>
                </div>
            </div>

            <!-- Dashboard Cards -->
            <div class="grid grid-3">
                
                <!-- Musica & Testi -->
                <a href="media.php" class="menu-card">
                    <div class="menu-card-icon">🎵</div>
                    <div class="menu-card-title">Musica & Testi</div>
                    <div class="menu-card-text">Sfoglia il catalogo completo</div>
                </a>

                <!-- Upload -->
                <a href="upload.php" class="menu-card">
                    <div class="menu-card-icon">📤</div>
                    <div class="menu-card-title">Upload Canzone</div>
                    <div class="menu-card-text">Pubblica i tuoi brani</div>
                </a>

                <!-- Profilo -->
                <a href="profile.php" class="menu-card">
                    <div class="menu-card-icon">👤</div>
                    <div class="menu-card-title">Il mio Profilo</div>
                    <div class="menu-card-text">Modifica dati e preferenze</div>
                </a>

                <!-- Admin (solo se admin) -->
                <?php if ($user['is_admin']): ?>
                <a href="admin.php" class="menu-card menu-card-admin">
                    <div class="menu-card-icon">🔒</div>
                    <div class="menu-card-title menu-card-title-admin">Admin Panel</div>
                    <div class="menu-card-text">Gestione utenti e sito</div>
                </a>
                <?php endif; ?>

            </div>

        </div>
    </div>

</body>
</html>