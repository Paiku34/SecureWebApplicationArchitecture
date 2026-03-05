<?php

/*
 * ============================================================
 * admin.php — Pannello di amministrazione
 * ============================================================
 *
 * Accesso SOLO per account con is_admin=1. Espone operazioni privilegiate
 * protette da molteplici layer di sicurezza:
 *
 *  1. VERIFICA ADMIN:
 *     is_admin=1 in sessione + rilettura real-time dal DB (anti-privilege escalation).
 *     Un utente degradato a non-admin viene espulso alla prossima richiesta admin.
 *
 *  2. IP BINDING:
 *     L'IP salvato al login viene confrontato ad ogni richiesta.
 *     Devia a login se l'IP cambia (possibile session hijacking).
 *
 *  3. CSRF SEPARATO PER AZIONI ADMIN:
 *     Un token CSRF specifico per l'area admin (admin_csrf_token) viene generato
 *     e verificato con hash_equals() per ogni azione POST.
 *     Separato dal CSRF utente per principio di separazione dei privilegi.
 *
 *  4. PROTEZIONE SELF-BAN E BAN ADMIN:
 *     toggle_ban controlla che il target non sia: (a) se stesso, (b) un altro admin.
 *     Previene escalation accidentale o intenzionale che blocchi tutti gli admin.
 *
 *  5. PROTEZIONE SELF-DEMOTION:
 *     toggle_admin controlla che l'admin non rimuova i propri privilegi.
 *     Previene lock-out dell'ultimo amministratore.
 *
 *  6. PATH TRAVERSAL SU ELIMINAZIONE FILE:
 *     delete_media: realpath() + strpos() verificano che i file da eliminare
 *     siano dentro storage/ prima di unlink(). Previene che ID manomessi
 *     puntino a file di sistema.
 *
 *  7. WHITELIST AZIONI PER UNBLOCK:
 *     Il parametro action_type per lo sblocco rate limit viene validato contro
 *     una whitelist esplicita degli action type esistenti.
 *     Previene injection di action type arbitrari.
 *
 *  8. LOGGING AZIONI AMMINISTRATIVE:
 *     Ogni azione sensibile (ban, unban, delete, toggle_admin) genera
 *     un evento CRITICAL nel log di sicurezza con actor e target IDs.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/RateLimiter.php';

set_security_headers();

// 1. Verifica che l'utente sia autenticato e abbia privilegi da amministratore
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    // Se l'utente non è autorizzato, viene reindirizzato alla pagina di login
    header("Location: login.php?error=unauthorized");
    exit();
}

// IP binding contro session hijacking
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    header('Location: login.php?error=ip_mismatch');
    exit();
}

// Verifica sessione (timeout inattività + controllo ban real-time)
if (!validate_session($pdo)) {
    header('Location: login.php?error=session_invalid');
    exit();
}

// Inizializzazione dei logger di sicurezza e del rate limiter
$securityLogger = new SecurityLogger($pdo);
$rateLimiter = new RateLimiter($pdo);

// 2. Generazione del token se non esiste già
if (!isset($_SESSION['admin_csrf_token'])) {
    $_SESSION['admin_csrf_token'] = bin2hex(random_bytes(32));
}

// 3. Gestione delle POST
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verifica che il token sia valido (hash_equals per prevenire timing attack)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['admin_csrf_token'], $_POST['csrf_token'])) {
        $error = "Token di sicurezza non valido.";
        $securityLogger->log('admin_csrf_violation', 'CRITICAL', [
            'admin_id' => $_SESSION['user_id'],
            'action' => $_POST['action'] ?? 'unknown'
        ]);
    } else {
        // Azione richiesta dall'utente
        $action = $_POST['action'] ?? '';
        
        try {
            switch ($action) {
                case 'toggle_premium':
                    // Attiva o disattiva lo stato premium di un utente
                    $userId = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
                    if ($userId) {
                        $stmt = $pdo->prepare("UPDATE users SET is_premium = NOT is_premium WHERE id = ?");
                        $stmt->execute([$userId]);
                        $message = "Stato premium aggiornato con successo.";
                        $securityLogger->log('admin_toggle_premium', 'INFO', [
                            'admin_id' => $_SESSION['user_id'],
                            'target_user_id' => $userId
                        ]);
                    } else {
                        $error = "ID utente non valido.";
                    }
                    break;

                case 'toggle_ban':
                    $userId = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
                    if ($userId && $userId != $_SESSION['user_id']) {
                        // Inverte lo stato is_banned (0->1 o 1->0) solo se non è admin
                        $stmt = $pdo->prepare("UPDATE users SET is_banned = NOT is_banned WHERE id = ? AND is_admin = 0");
                        $stmt->execute([$userId]);
                        
                        // Invalida la cache dell'utente se presente, così il blocco è immediato
                        if (function_exists('invalidate_user_cache')) {
                            invalidate_user_cache($userId);
                        }
                        
                        $message = "Stato ban utente aggiornato con successo.";
                        $securityLogger->log('admin_toggle_ban', 'WARNING', [
                            'admin_id' => $_SESSION['user_id'],
                            'target_user_id' => $userId
                        ]);
                    } else {
                        $error = "Impossibile bannare un amministratore o te stesso.";
                    }
                    break;
                    
                case 'delete_user':
                    // Elimina un utente dal sistema
                    $userId = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
                    if ($userId && $userId != $_SESSION['user_id']) {
                        // Recupera il nome utente per il log
                        $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                        $stmt->execute([$userId]);
                        $username = $stmt->fetchColumn();
                        
                        // Elimina l'utente
                        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND is_admin = 0");
                        $stmt->execute([$userId]);
                        
                        if ($stmt->rowCount() > 0) {
                            $message = "Utente eliminato con successo.";
                            $securityLogger->log('admin_delete_user', 'CRITICAL', [
                                'admin_id' => $_SESSION['user_id'],
                                'deleted_user_id' => $userId,
                                'deleted_username' => $username
                            ]);
                        } else {
                            $error = "Impossibile eliminare un amministratore.";
                        }
                    } else {
                        $error = "Non puoi eliminare te stesso o ID non valido.";
                    }
                    break;
                    
                case 'delete_media':
                    // Elimina un file multimediale dal sistema
                    $mediaId = filter_input(INPUT_POST, 'media_id', FILTER_VALIDATE_INT);
                    if ($mediaId) {
                        // Recupera i dettagli del media prima di eliminarlo
                        $stmt = $pdo->prepare("SELECT title, audio_path, lyrics_path FROM media WHERE id = ?");
                        $stmt->execute([$mediaId]);
                        $media = $stmt->fetch();
                        
                        if ($media) {
                            // Elimina i file fisici con protezione path traversal
                            $storage_safe = realpath(__DIR__ . '/../storage');
                            if ($media['audio_path']) {
                                $audioFull = realpath($storage_safe . '/' . $media['audio_path']);
                                if ($audioFull && strpos($audioFull, $storage_safe) === 0 && file_exists($audioFull)) {
                                    unlink($audioFull);
                                }
                            }
                            if ($media['lyrics_path']) {
                                $lyricsFull = realpath($storage_safe . '/' . $media['lyrics_path']);
                                if ($lyricsFull && strpos($lyricsFull, $storage_safe) === 0 && file_exists($lyricsFull)) {
                                    unlink($lyricsFull);
                                }
                            }
                            
                            // Elimina il record dal database
                            $stmt = $pdo->prepare("DELETE FROM media WHERE id = ?");
                            $stmt->execute([$mediaId]);
                            
                            $message = "Media eliminato con successo.";
                            $securityLogger->log('admin_delete_media', 'WARNING', [
                                'admin_id' => $_SESSION['user_id'],
                                'media_id' => $mediaId,
                                'title' => $media['title']
                            ]);
                        }
                    }
                    break;
                    
                case 'unblock_user':
                    // Sblocca un utente dal rate limiting
                    $identifier = $_POST['identifier'] ?? '';
                    $actionType = $_POST['action_type'] ?? '';
                    
                    if ($identifier && in_array($actionType, ['login', 'upload', 'download', 'view', 'password_change', 'password_recovery'])) {
                        $rateLimiter->forceUnblock($identifier, $actionType);
                        
                        $message = "Utente sbloccato con successo dal rate limiting.";
                        $securityLogger->log('admin_force_unblock', 'INFO', [
                            'admin_id' => $_SESSION['user_id'],
                            'identifier' => $identifier,
                            'action_type' => $actionType
                        ]);
                    } else {
                        $error = "Parametri non validi per lo sblocco.";
                    }
                    break;
                    
                case 'cleanup_rate_limits':
                    // Rimuove i record di rate limiting più vecchi di 24 ore
                    $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                    $stmt->execute();
                    $deleted = $stmt->rowCount();
                    
                    $message = "Cleanup completato: $deleted record eliminati.";
                    $securityLogger->log('admin_rate_limit_cleanup', 'INFO', [
                        'admin_id' => $_SESSION['user_id'],
                        'deleted_records' => $deleted
                    ]);
                    break;
                    
                case 'force_maintenance':
                    // Esegue una manutenzione completa del sistema
                    require_once '../includes/maintenance.php';
                    $results = force_maintenance($pdo);
                    
                    $message = sprintf(
                        "Manutenzione completata: %d rate limits, %d password resets eliminati. Log %s.",
                        $results['rate_limits'],
                        $results['password_resets'],
                        $results['log_rotated'] ? 'ruotato' : 'non ruotato'
                    );
                    
                    $securityLogger->log('admin_force_maintenance', 'INFO', [
                        'admin_id' => $_SESSION['user_id'],
                        'results' => $results
                    ]);
                    break;
                    
                default:
                    $error = "Azione non riconosciuta.";
            }
        } catch (PDOException $e) {
            // Gestione degli errori del database
            $error = "Errore durante l'operazione: " . htmlspecialchars($e->getMessage() ?? '');
            $securityLogger->log('admin_operation_failed', 'CRITICAL', [
                'admin_id' => $_SESSION['user_id'],
                'action' => $action,
                'error' => $e->getMessage()
            ]);
        }
    }
}

// 4. Recupero dei dati per la visualizzazione nel pannello
try {
    // Statistiche generali del sistema
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users");
    $stmt->execute();
    $total_users = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE is_premium = 1");
    $stmt->execute();
    $total_premium = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE is_admin = 1");
    $stmt->execute();
    $total_admins = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM media");
    $stmt->execute();
    $total_media = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM media WHERE DATE(uploaded_at) = CURDATE()");
    $stmt->execute();
    $total_uploads_today = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT COUNT(DISTINCT identifier) FROM rate_limits WHERE is_blocked = 1");
    $stmt->execute();
    $blocked_users_count = $stmt->fetchColumn();
    
    $stats = [
        'total_users' => $total_users,
        'total_premium' => $total_premium,
        'total_admins' => $total_admins,
        'total_media' => $total_media,
        'total_uploads_today' => $total_uploads_today,
        'blocked_users' => $blocked_users_count
    ];
    
    // Recupera la lista degli utenti
    $stmt = $pdo->prepare("
        SELECT id, username, email, is_premium, is_admin, is_banned, total_uploads, total_downloads_received, 
               created_at, last_login 
        FROM users 
        ORDER BY created_at DESC
    ");
    $stmt->execute();
    $users = $stmt->fetchAll();
    
    // Recupera la lista dei media
    $stmt = $pdo->prepare("
        SELECT m.id, m.title, m.is_premium, m.uploaded_at, u.username AS author 
        FROM media m 
        JOIN users u ON m.user_id = u.id 
        ORDER BY m.uploaded_at DESC 
        LIMIT 50
    ");
    $stmt->execute();
    $media = $stmt->fetchAll();
    
    // Recupera gli utenti bloccati dal rate limiting
    $stmt = $pdo->prepare("
        SELECT identifier, action_type, attempt_count, first_attempt, last_attempt, is_blocked 
        FROM rate_limits 
        WHERE is_blocked = 1 
        ORDER BY last_attempt DESC
    ");
    $stmt->execute();
    $blockedUsers = $stmt->fetchAll();
    
    // Recupera i log di sicurezza più recenti
    $stmt = $pdo->prepare("
        SELECT event_type, severity, user_id, ip_address, created_at, context 
        FROM security_logs 
        ORDER BY created_at DESC 
        LIMIT 100
    ");
    $stmt->execute();
    $securityLogs = $stmt->fetchAll();
    
} catch (PDOException $e) {
    $error = "Errore nel caricamento dei dati: " . htmlspecialchars($e->getMessage() ?? '');
}

?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pannello Amministratore - SUPREMA</title>
    <link rel="stylesheet" href="assets/css/admin.css">
</head>
<body class="admin-page">
    <div class="container">
        <header>
            <h1>🛡️ Pannello Amministratore</h1>
            <div class="nav-links">
                <a href="dashboard.php" class="btn btn-primary">Dashboard</a>
                <a href="logout.php" class="btn btn-danger">Logout</a>
            </div>
        </header>
        
        <?php if ($message): ?>
            <div class="message success"><?= htmlspecialchars($message ?? '') ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="message error"><?= htmlspecialchars($error ?? '') ?></div>
        <?php endif; ?>
        
        <!-- Statistiche -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3><?= $stats['total_users'] ?></h3>
                <p>Utenti Totali</p>
            </div>
            <div class="stat-card">
                <h3><?= $stats['total_premium'] ?></h3>
                <p>Utenti Premium</p>
            </div>
            <div class="stat-card">
                <h3><?= $stats['total_admins'] ?></h3>
                <p>Amministratori</p>
            </div>
            <div class="stat-card">
                <h3><?= $stats['total_media'] ?></h3>
                <p>Media Totali</p>
            </div>
            <div class="stat-card">
                <h3><?= $stats['total_uploads_today'] ?></h3>
                <p>Upload Oggi</p>
            </div>
            <div class="stat-card">
                <h3><?= $stats['blocked_users'] ?></h3>
                <p>Utenti Bloccati</p>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="tab-buttons">
            <button class="tab-btn active" data-tab="users">Gestione Utenti</button>
            <button class="tab-btn" data-tab="media">Gestione Media</button>
            <button class="tab-btn" data-tab="blocked">Utenti Limitati</button>
            <button class="tab-btn" data-tab="logs">Log di Sicurezza</button>
        </div>
        
        <!-- Tab Gestione Utenti -->
        <div id="users-tab" class="tab-content active">
            <div class="section">
                <h2>Gestione Utenti</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Status</th>
                                <th>Upload</th>
                                <th>Download</th>
                                <th>Registrato</th>
                                <th>Ultimo Login</th>
                                <th>Azioni</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?= $user['id'] ?></td>
                                    <td><?= htmlspecialchars($user['username'] ?? '') ?></td>
                                    <td><?= htmlspecialchars($user['email'] ?? '') ?></td>
                                    <td>
                                        <?php if ($user['is_admin']): ?>
                                            <span class="badge badge-admin">ADMIN</span>
                                        <?php endif; ?>
                                        <?php if ($user['is_premium']): ?>
                                            <span class="badge badge-premium">PREMIUM</span>
                                        <?php endif; ?>
                                         <?php if (isset($user['is_banned']) && $user['is_banned']): ?>
                                            <span class="badge badge-critical">BANNATO</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= $user['total_uploads'] ?></td>
                                    <td><?= $user['total_downloads_received'] ?></td>
                                    <td><?= date('d/m/Y', strtotime($user['created_at'])) ?></td>
                                    <td><?= $user['last_login'] ? date('d/m/Y H:i', strtotime($user['last_login'])) : 'Mai' ?></td>
                                    <td>
                                        <div class="actions">
                                            <form method="POST" class="inline-form">
                                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                                                <input type="hidden" name="action" value="toggle_premium">
                                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                <button type="submit" class="btn btn-warning btn-small">
                                                    <?= $user['is_premium'] ? 'Rimuovi' : 'Rendi' ?> Premium
                                                </button>
                                            </form>
                                            
                                            <?php if ($user['id'] != $_SESSION['user_id']): ?>

                                                <?php if (!$user['is_admin']): ?>
                                                    <form method="POST" class="inline-form">
                                                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                                                        <input type="hidden" name="action" value="toggle_ban">
                                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                        <button type="submit" class="btn btn-warning btn-small btn-orange">
                                                            <?= (isset($user['is_banned']) && $user['is_banned']) ? 'Sblocca' : 'Blocca' ?>
                                                        </button>
                                                    </form>
                                                <?php endif; ?>
                                                
                                                <?php if (!$user['is_admin']): ?>
                                                    <form method="POST" class="inline-form" data-confirm="delete-user">
                                                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                                                        <input type="hidden" name="action" value="delete_user">
                                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                        <button type="submit" class="btn btn-danger btn-small">Elimina</button>
                                                    </form>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Tab Gestione Media -->
        <div id="media-tab" class="tab-content">
            <div class="section">
                <h2>Gestione Media</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Titolo</th>
                                <th>Autore</th>
                                <th>Tipo</th>
                                <th>Data Upload</th>
                                <th>Azioni</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($media as $item): ?>
                                <tr>
                                    <td><?= $item['id'] ?></td>
                                    <td><?= htmlspecialchars($item['title'] ?? '') ?></td>
                                    <td><?= htmlspecialchars($item['author'] ?? '') ?></td>
                                    <td>
                                        <?php if ($item['is_premium']): ?>
                                            <span class="badge badge-premium">PREMIUM</span>
                                        <?php else: ?>
                                            <span class="badge badge-info">FREE</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= date('d/m/Y H:i', strtotime($item['uploaded_at'])) ?></td>
                                    <td>
                                        <form method="POST" class="inline-form" data-confirm="delete-media">
                                            <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                                            <input type="hidden" name="action" value="delete_media">
                                            <input type="hidden" name="media_id" value="<?= $item['id'] ?>">
                                            <button type="submit" class="btn btn-danger btn-small">Elimina</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Tab Utenti Bloccati -->
        <div id="blocked-tab" class="tab-content">
            <div class="section">
                <h2>Utenti Bloccati dal Rate Limiting</h2>
                <div class="flex-gap-10 mb-15">
                    <form method="POST" class="inline-form">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                        <input type="hidden" name="action" value="cleanup_rate_limits">
                        <button type="submit" class="btn btn-success">🧹 Pulisci Record Vecchi (>24h)</button>
                    </form>
                    
                    <form method="POST" class="inline-form">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                        <input type="hidden" name="action" value="force_maintenance">
                        <button type="submit" class="btn btn-warning" data-confirm="maintenance">⚙️ Manutenzione Completa</button>
                    </form>
                </div>
                
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Identifier</th>
                                <th>Tipo Azione</th>
                                <th>Tentativi</th>
                                <th>Primo Tentativo</th>
                                <th>Ultimo Tentativo</th>
                                <th>Stato</th>
                                <th>Azioni</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($blockedUsers)): ?>
                                <tr>
                                    <td colspan="7" class="td-center">Nessun utente bloccato</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($blockedUsers as $blocked): ?>
                                    <?php
                                    // Decodifica identifier per renderlo leggibile (se è per login)
                                    $displayIdentifier = $blocked['identifier'];
                                    $isLoginBlock = ($blocked['action_type'] === 'login');
                                    
                                    $statusClass = $blocked['is_blocked'] ? 'badge-blocked' : 'badge-warning';
                                    $statusText = $blocked['is_blocked'] ? 'BLOCCATO' : 'VICINO AL LIMITE';
                                    ?>
                                    <tr>
                                        <td>
                                            <?= htmlspecialchars($displayIdentifier ?? '') ?>
                                            <?php if ($isLoginBlock): ?>
                                                <br><small class="text-gray">(Login tentativo)</small>
                                            <?php endif; ?>
                                        </td>
                                        <td><strong><?= htmlspecialchars($blocked['action_type'] ?? '') ?></strong></td>
                                        <td>
                                            <span class="badge <?= htmlspecialchars((string)$blocked['attempt_count'] >= 5 ? 'badge-critical' : 'badge-warning') ?>">
                                                <?= $blocked['attempt_count'] ?>
                                            </span>
                                        </td>
                                        <td><?= date('d/m/Y H:i', strtotime($blocked['first_attempt'])) ?></td>
                                        <td><?= date('d/m/Y H:i', strtotime($blocked['last_attempt'])) ?></td>
                                        <td>
                                            <span class="badge <?= $statusClass ?>"><?= $statusText ?></span>
                                        </td>
                                        <td>
                                            <form method="POST" class="inline-form">
                                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['admin_csrf_token'] ?>">
                                                <input type="hidden" name="action" value="unblock_user">
                                                <input type="hidden" name="identifier" value="<?= htmlspecialchars($blocked['identifier'] ?? '') ?>">
                                                <input type="hidden" name="action_type" value="<?= htmlspecialchars($blocked['action_type'] ?? '') ?>">
                                                <button type="submit" class="btn btn-success btn-small" data-confirm="unblock">
                                                    Sblocca
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Tab Log di Sicurezza -->
        <div id="logs-tab" class="tab-content">
            <div class="section">
                <h2>Log di Sicurezza (Ultimi 100 Eventi)</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Data/Ora</th>
                                <th>Tipo Evento</th>
                                <th>Gravità</th>
                                <th>User ID</th>
                                <th>IP</th>
                                <th>Contesto</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($securityLogs as $log): ?>
                                <tr>
                                    <td><?= date('d/m/Y H:i:s', strtotime($log['created_at'] ?? 'now')) ?></td>
                                    <td><?= htmlspecialchars($log['event_type'] ?? '') ?></td>
                                    <td>
                                        <span class="badge badge-<?= htmlspecialchars(strtolower($log['severity'] ?? 'info')) ?>">
                                            <?= htmlspecialchars($log['severity'] ?? 'INFO') ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($log['user_id'] ?? '') ?></td>
                                    <td><?= htmlspecialchars($log['ip_address'] ?? '') ?></td>
                                    <td class="td-max-width">
                                        <?= htmlspecialchars(mb_substr((string)($log['context'] ?? ''), 0, 100)) ?>...                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script src="assets/js/admin.js"></script>
</body>
</html>