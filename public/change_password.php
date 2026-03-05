<?php
/*
 * ============================================================
 * change_password.php — Cambio password utente autenticato
 * ============================================================
 *
 * Permette all'utente loggato di cambiare la propria password con le seguenti
 * misure di sicurezza:
 *
 *  1. VERIFICA SESSIONE + IP BINDING:
 *     validate_session() + controllo IP. Session hijacking bloccato.
 *
 *  2. PROTEZIONE CSRF:
 *     Token CSRF verificato con hash_equals() prima di processare.
 *
 *  3. VALIDAZIONE INPUT BASE:
 *     - Password attuale: non vuota, max 256 char
 *     - Nuova password: min 12 char, max 256 char
 *     - Conferma password: deve coincidere con la nuova
 *     - Nuova password: deve essere DIVERSA dall'attuale (no cambio inutile)
 *
 *  4. PASSWORD STRENGTH ENFORCEMENT:
 *     Stesso algoritmo di register.php e recover.php (score 100/100 obbligatorio).
 *     Implementato lato server (PHP) indipendentemente dal client.
 *
 *  5. RATE LIMITING (3/giorno):
 *     Max 3 tentativi di cambio password al giorno per utente.
 *     Previene brute force della password attuale da parte di chi ha accesso
 *     alla sessione ma non conosce la password.
 *     IMPORTANTE: il rate limit viene consumato SOLO quando si tenta la verifica
 *     della vecchia password, non per errori di input (lunghezza, mismatch).
 *     Se il limite è esaurito, la sessione viene distrutta (logout forzato)
 *     per evitare che una sessione rubata sia usata per cicli di attacco.
 *
 *  6. VERIFICA PASSWORD ATTUALE:
 *     password_verify() sull'hash dal DB conferma che il richiedente è
 *     il legittimo proprietario dell'account (autenticazione richiesta).
 *
 *  7. ARGON2ID HASHING:
 *     La nuova password viene hashata con PASSWORD_ARGON2ID prima del salvataggio.
 *
 *  8. RESET RATE LIMIT DOPO SUCCESSO:
 *     Dopo un cambio riuscito, il contatore viene resettato per non penalizzare
 *     l'utente che cambia la password legittimamente.
 */
declare(strict_types=1);

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/RateLimiter.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php';

$rateLimiter = new RateLimiter($pdo);
$securityLogger = new SecurityLogger($pdo);
$error = '';

// controllo accesso
if (!isset($_SESSION['user_id']) || !validate_session($pdo)) {
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// ip binding - blocca session hijacking
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('change_password', 'IP mismatch');
    session_destroy();
    header('Location: login.php?error=ip_mismatch');
    exit();
}

// genera csrf se non esiste
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// recupera dati utente
$user = get_user_data($pdo, $_SESSION['user_id'], false);
if (!$user) {
    session_destroy();
    header('Location: login.php?error=user_not_found');
    exit();
}

// valutazione forza password
function evaluatePasswordStrength(string $password): array {
    $score = 0;
    $missing = [];
    $feedback = [];
    $length = mb_strlen($password, 'UTF-8');
    
    $score += ($length >= 12) ? 40 : (($length >= 10) ? 25 : 10);
    if ($length < 12) $missing[] = "lunghezza";
    
    if (preg_match('/[a-z]/', $password)) $score += 10; else $missing[] = "minuscole";
    if (preg_match('/[A-Z]/', $password)) $score += 10; else $missing[] = "maiuscole";
    if (preg_match('/[0-9]/', $password)) $score += 15; else $missing[] = "numeri";
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 25; else $missing[] = "simboli";
    
    if (preg_match('/(password|12345|qwerty|admin|welcome|letmein)/i', $password)) { $score -= 20; $feedback[] = "Evita parole comuni"; }
    if (preg_match('/(.)\1{2,}/', $password)) { $score -= 10; $feedback[] = "Evita ripetizioni"; }
    
    $score = max(0, min(100, $score));
    $allFeedback = array_merge($missing ? ["Manca: " . implode(', ', $missing)] : [], $feedback);
    
    return ['score' => $score, 'feedback' => implode('. ', $allFeedback), 'complete' => empty($missing)];
}

// gestione form POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // verifica csrf prima di tutto
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
        $error = "Token CSRF non valido.";
    } else {
        $old_pass = $_POST['old_password'] ?? '';
        $new_pass = $_POST['new_password'] ?? '';
        $confirm_pass = $_POST['confirm_password'] ?? '';
        // $logout_all = isset($_POST['logout_all_devices']);
        
        // validazioni base, non consumano tentativi rate limit
        if (!is_nonempty_string($old_pass, 256)) {
            $error = "Password attuale non valida.";
        } elseif (!is_nonempty_string($new_pass, 256) || mb_strlen($new_pass, 'UTF-8') < 12) {
            $error = "Nuova password: min 12 caratteri.";
        } elseif ($new_pass !== $confirm_pass) {
            $error = "Le password non coincidono.";
        } elseif ($old_pass === $new_pass) {
            $error = "Nuova password deve essere diversa.";
        } else {
            // check forza password
            $strength = evaluatePasswordStrength($new_pass);
            if ($strength['score'] < 100 || !$strength['complete']) {
                $error = "Password richiede score 100/100 con tutte le categorie. " . $strength['feedback'];
            } else {
                // rate limit solo per verifica password vecchia 
                $user_identifier = (int)$_SESSION['user_id'];
                
                if ($rateLimiter->isBlocked($user_identifier, 'password_change')) {
                    // Distruzione sessione e redirect al login
                    session_unset();
                    session_destroy();
                    header('Location: login.php?error=too_many_attempts');
                    exit();
                } else {
                    // verifica password attuale
                    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
                    $stmt->execute([$_SESSION['user_id']]);
                    $db_user = $stmt->fetch();
                    
                    if (!$db_user || !password_verify($old_pass, $db_user['password_hash'])) {
                        // Incrementa il contatore solo sul fallimento
                        $rateLimiter->recordFailedAttempt($user_identifier, 'password_change');
                        $error = "Password attuale errata.";
                        $securityLogger->log('password_change_wrong_old', 'WARNING', ['user_id' => $_SESSION['user_id']]);
                    } else {
                        // Resetta il contatore: verifica riuscita non deve penalizzare
                        $rateLimiter->resetLimit($user_identifier, 'password_change');
                        // aggiorna password
                        $hashedPassword = password_hash($new_pass, PASSWORD_ARGON2ID);
                        $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                        $stmt->execute([$hashedPassword, $_SESSION['user_id']]);
                        
                        // // logout altri dispositivi se richiesto
                        // if ($logout_all) {
                        //     $current_session = session_id();
                        //     $stmt = $pdo->prepare("DELETE FROM sessions WHERE user_id = ? AND session_id != ?");
                        //     $stmt->execute([$_SESSION['user_id'], $current_session]);
                        // }
                        
                        $securityLogger->log('password_changed', 'INFO', [
                            'user_id' => $_SESSION['user_id'],
                            'ip' => $_SERVER['REMOTE_ADDR']
                            // 'logout_all' => $logout_all
                        ]);
                        
                        // Flash message e redirect a dashboard
                        $_SESSION['flash_message'] = 'Password cambiata con successo!';
                        $_SESSION['flash_type'] = 'success';
                        header('Location: dashboard.php');
                        exit();
                    }
                }
            }
        }
    }
}

set_security_headers();
$username_safe = htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cambio Password - Music Platform</title>
    <link rel="stylesheet" href="assets/css/main.css">
    <link rel="stylesheet" href="assets/css/password-strength.css">
</head>
<body class="auth-page">
    
    <div class="auth-container auth-container-wide">
        <!-- Header -->
        <div class="text-center mb-20">
            <h1>🔒 Cambio Password</h1>
            <p class="text-muted">Ciao, <strong><?= $username_safe ?></strong> — Aggiorna le tue credenziali</p>
        </div>
        
        <!-- Alert Errore -->
        <?php if ($error): ?>
            <div class="message message-error">
                <strong>Errore</strong><br>
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>
        
        <!-- Form Card -->
        <form method="POST" class="card">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
            
            <!-- Password Attuale -->
            <div class="form-group">
                <label for="old_password" class="form-label">
                    Password Attuale
                </label>
                <div class="password-input-wrap">
                    <input 
                        type="password" 
                        id="old_password" 
                        name="old_password" 
                        required 
                        maxlength="256"
                        class="form-input"
                        placeholder="Inserisci password attuale"
                    >
                    <button 
                        type="button" 
                        data-toggle-password="old_password" 
                        class="btn btn-secondary btn-sm password-toggle"
                        title="Mostra/Nascondi"
                    >
                        👁️
                    </button>
                </div>
            </div>
            
            <!-- Nuova Password -->
            <div class="form-group">
                <label for="new_password" class="form-label">
                    Nuova Password
                </label>
                <div class="password-input-wrap">
                    <input 
                        type="password" 
                        id="new_password" 
                        name="new_password" 
                        required 
                        minlength="12" 
                        maxlength="256"
                        class="form-input"
                        placeholder="Almeno 12 caratteri con maiuscole, numeri e simboli"
                    >
                    <button 
                        type="button" 
                        data-toggle-password="new_password" 
                        class="btn btn-secondary btn-sm password-toggle"
                        title="Mostra/Nascondi"
                    >
                        👁️
                    </button>
                </div>
                
                <!-- Indicatore Strength -->
                <div id="strength-indicator" class="strength-indicator">
                    <div class="strength-header">
                        <strong id="strength-label">Sicurezza:</strong>
                        <span id="strength-score"></span>
                    </div>
                    <div class="strength-bar">
                        <div id="strength-bar-fill" class="strength-bar-fill"></div>
                    </div>
                    <p id="strength-feedback" class="strength-feedback"></p>
                </div>

                <!-- Requisiti Password -->
                <ul class="password-requirements" id="requirements">
                    <li id="req-length">✗ Almeno 12 caratteri</li>
                    <li id="req-lower">✗ Lettere minuscole (a-z)</li>
                    <li id="req-upper">✗ Lettere MAIUSCOLE (A-Z)</li>
                    <li id="req-number">✗ Numeri (0-9)</li>
                    <li id="req-symbol">✗ Simboli (!@#$%...)</li>
                </ul>
            </div>
            
            <!-- Conferma Password -->
            <div class="form-group">
                <label for="confirm_password" class="form-label">
                    Conferma Nuova Password
                </label>
                <div>
                    <input 
                        type="password" 
                        id="confirm_password" 
                        name="confirm_password" 
                        required 
                        maxlength="256"
                        class="form-input"
                        placeholder="Ripeti la nuova password"
                    >
                </div>
            </div>
            
            <!-- Separator -->
            <div class="section-divider"></div>
            
            <!-- Bottoni -->
            <div class="btn-row-wrap">
                <a 
                    href="dashboard.php" 
                    class="btn btn-secondary btn-flex"
                >
                    ← Annulla
                </a>
                <button 
                    type="submit" 
                    id="submit-btn"
                    class="btn btn-primary btn-flex"
                >
                    ✨ Cambia Password
                </button>
            </div>
        </form>
        
        <!-- Footer Links -->
        <div class="text-center mt-20">
            <a href="recover.php" class="link-secondary">❓ Ho dimenticato la password</a>
        </div>
    </div>

    <script src="assets/js/change-password.js"></script>
</body>
</html>
