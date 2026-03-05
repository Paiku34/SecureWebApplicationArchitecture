<?php
/*
 * media.php - Catalogo contenuti multimediali
 * 
 * Mostra lista brani con filtro premium/free.
 * Controllo sessione, IP binding, caching permessi utente.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/media_db.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php';

$securityLogger = new SecurityLogger($pdo);

// controllo sessione
if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('media', 'No session');
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// ip binding
if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('media', 'IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Indirizzo IP non corrispondente.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

if (!validate_session($pdo)) {
    header('Location: login.php?error=session_invalid');
    exit();
}

// recupera dati utente con cache
$userStatus = get_user_data($pdo, $_SESSION['user_id'], false);

if (!$userStatus) {
    $securityLogger->log('user_not_found', 'WARNING', [
        'user_id' => $_SESSION['user_id']
    ]);
    session_destroy();
    $_SESSION['flash_message'] = 'Account non trovato. Effettua il login.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=account_not_found');
    exit();
}

// Usiamo il valore fresco dal DB per il filtraggio
$current_is_premium = (bool)$userStatus['is_premium'];
$current_username = htmlspecialchars($userStatus['username'] ?? '', ENT_QUOTES, 'UTF-8');
$mediaList = getVisibleMedia($pdo, $current_is_premium);

// log primo accesso nella sessione
if (!isset($_SESSION['media_logged'])) {
    $securityLogger->log('media_catalog_access', 'INFO', [
        'user_id' => $_SESSION['user_id'],
        'is_premium' => $current_is_premium,
        'items_visible' => count($mediaList)
    ]);
    $_SESSION['media_logged'] = true;
}

set_security_headers();
?>

<!DOCTYPE html>
<html class="dark" lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catalogo Multimediale - Music Project</title>
    
    <!-- Local Fonts -->
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <!-- Header -->
    <header class="header">
        <a href="dashboard.php" class="header-brand">
            🎵 Music Project
        </a>
        <nav class="header-nav">
            <a href="dashboard.php">Dashboard</a>
            <a href="media.php" class="active">Catalogo</a>
            <a href="upload.php">Upload</a>
            <a href="profile.php">Profilo</a>
        </nav>
        <div class="header-user">
            <a href="logout.php" class="btn btn-primary btn-sm">Logout</a>
            <div class="user-avatar">
                <?php echo strtoupper(substr($current_username, 0, 1)); ?>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <div class="main-content">
        <div class="container">
            
            <!-- Page Header -->
            <div class="card-header">
                <div>
                    <h1 class="card-title">Catalogo Multimediale</h1>
                    <p class="card-subtitle">Gestisci e scarica i tuoi brani preferiti</p>
                </div>
                <div class="inline-flex-row-wrap">
                    <?php if ($current_is_premium): ?>
                        <span class="badge badge-premium">⭐ Catalogo Premium</span>
                    <?php else: ?>
                        <span class="badge badge-standard">📚 Catalogo Standard</span>
                    <?php endif; ?>
                    <a href="dashboard.php" class="btn btn-secondary btn-sm">← Dashboard</a>
                </div>
            </div>

            <!-- Search -->
            <div class="search-container">
                <input 
                    type="text" 
                    id="mediaSearch" 
                    class="search-input" 
                    placeholder="🔍 Cerca per titolo, autore o genere..."
                />
            </div>

            <!-- Table -->
            <div class="table-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Titolo</th>
                            <th>Autore</th>
                            <th class="text-center">Accesso</th>
                            <th class="text-right">Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($mediaList)): ?>
                            <tr>
                                <td colspan="4" class="text-center-wide">
                                    <div class="icon-xl mb-10">🎵</div>
                                    <h3 class="mb-10">Nessun contenuto disponibile</h3>
                                    <p class="text-muted">
                                        <?php echo $current_is_premium ? 'Il catalogo è vuoto al momento.' : 'Effettua l\'upgrade per accedere al catalogo completo.'; ?>
                                    </p>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($mediaList as $song): 
                                $title_safe = htmlspecialchars($song['title'] ?? '', ENT_QUOTES, 'UTF-8');
                                $author_safe = htmlspecialchars($song['author_name'] ?? '', ENT_QUOTES, 'UTF-8');
                                $song_id = (int)$song['id'];
                                $user_id = (int)$song['user_id'];
                                $is_premium_content = (bool)$song['is_premium'];
                                $has_audio = !empty($song['audio_path']);
                                $has_lyrics = !empty($song['lyrics_path']);
                            ?>
                            <tr>
                                <td>
                                    <div class="inline-flex-row">
                                        <div class="icon-lg">🎵</div>
                                        <strong><?php echo $title_safe; ?></strong>
                                    </div>
                                </td>
                                
                                <td>
                                    <a href="user_profile.php?id=<?php echo $user_id; ?>" class="text-primary">
                                        @<?php echo $author_safe; ?>
                                    </a>
                                </td>
                                
                                <td class="text-center">
                                    <?php if ($is_premium_content): ?>
                                        <span class="badge badge-premium">PREMIUM</span>
                                    <?php else: ?>
                                        <span class="badge badge-free">LIBERO</span>
                                    <?php endif; ?>
                                </td>
                                
                                <td>
                                    <div class="table-actions">
                                        <?php if ($has_lyrics): ?>
                                            <a href="view_lyrics.php?id=<?php echo $song_id; ?>" class="btn btn-secondary btn-sm">
                                                📄 Testo
                                            </a>
                                        <?php endif; ?>
                                        
                                        <?php if ($has_audio): ?>
                                            <a href="download.php?id=<?php echo $song_id; ?>" class="btn btn-primary btn-sm">
                                                ⬇️ Audio
                                            </a>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

        </div>
    </div>
    
    <script src="assets/js/media-search.js"></script>

</body>
</html>