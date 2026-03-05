<?php
/*
 * ============================================================
 * register.php — Registrazione nuovo utente
 * ============================================================
 *
 * Gestisce la creazione di nuovi account con le seguenti protezioni:
 *
 *  1. CSRF PROTECTION:
 *     Token in sessione verificato con hash_equals() prima di processare.
 *
 *  2. RATE LIMITING PER IP:
 *     Max 5 registrazioni/ora per IP. Previene la creazione massiva di account
 *     (account farming per spam, bot abuse, credential stuffing preparation).
 *
 *  3. ANTI-ENUMERATION USERNAME/EMAIL:
 *     Se username O email sono già in uso, viene mostrato un messaggio generico
 *     che non specifica quale campo sia duplicato. Questo previene che un attaccante
 *     possa scoprire gli username/email registrati nel sistema.
 *
 *  4. PASSWORD STRENGTH ENFORCEMENT:
 *     Requisiti minimi: >=12 caratteri, minuscole, maiuscole, numeri, simboli.
 *     Score calcolato sia lato client (JS real-time feedback) che lato server
 *     (PHP indipendente, non bypassabile). Score 100/100 e tutte le categorie
 *     presenti sono OBBLIGATORI. Senza questo la registrazione fallisce.
 *
 *  5. ARGON2ID HASHING:
 *     La password viene hashata con PASSWORD_ARGON2ID (OWASP recommended)
 *     prima di essere salvata. Il salt è generato automaticamente da PHP.
 *
 *  6. INPUT VALIDATION:
 *     Username: whitelist /[A-Za-z0-9_.-]{3,32}/ (normalize_username)
 *     Email:    filter_var FILTER_VALIDATE_EMAIL (RFC 5321/5322 compliant)
 *     Password: valutazione multi-criterio (lunghezza + categorie + pattern blacklist)
 *
 *  7. PREPARED STATEMENTS:
 *     Tutta l'interazione con il DB usa prepared statements (no SQL injection).
 */

declare(strict_types=1);

require_once '../includes/db.php';
require_once '../includes/authentication.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/RateLimiter.php';

set_security_headers();

$securityLogger = new SecurityLogger($pdo);
$rateLimiter = new RateLimiter($pdo);
$errors = ['username' => '', 'email' => '', 'password' => ''];
$message = '';
$messageType = 'error';

// Valuta password (PHP)
function evaluatePasswordStrength(string $password): array {
    $score = 0;
    $feedback = [];
    $missing = [];
    $length = mb_strlen($password, 'UTF-8');
    
    $score += ($length >= 12) ? 40 : (($length >= 10) ? 25 : 10);
    if ($length < 12) $missing[] = "lunghezza";
    
    if (preg_match('/[a-z]/', $password)) $score += 10; else $missing[] = "minuscole";
    if (preg_match('/[A-Z]/', $password)) $score += 10; else $missing[] = "maiuscole";
    if (preg_match('/[0-9]/', $password)) $score += 15; else $missing[] = "numeri";
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 25; else $missing[] = "simboli";
    
    if (preg_match('/(password|12345|qwerty|admin)/i', $password)) { $score -= 20; $feedback[] = "Evita parole comuni"; }
    if (preg_match('/(.)\1{2,}/', $password)) { $score -= 10; $feedback[] = "Evita ripetizioni"; }
    
    $score = max(0, min(100, $score));
    $strength = ($score >= 100) ? 'forte' : (($score >= 50) ? 'media' : 'debole');
    $allFeedback = array_merge($missing ? ["Manca: " . implode(', ', $missing)] : [], $feedback);
    
    return ['strength' => $strength, 'score' => $score, 'feedback' => implode('. ', $allFeedback), 'complete' => empty($missing)];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $message = "Token non valido.";
        log_security_event($pdo, 'CSRF_TOKEN_INVALID', 'WARNING', 'anonymous');
    } else {
        // Rate limiting: max 5 registrazioni per IP all'ora
        $ip_identifier = 'register_ip_' . $_SERVER['REMOTE_ADDR'];
        if (!$rateLimiter->checkLimit($ip_identifier, 'register')) {
            $message = "Troppi tentativi di registrazione. Riprova tra un'ora.";
            $securityLogger->log('register_rate_limit', 'WARNING', ['ip' => $_SERVER['REMOTE_ADDR']]);
        } else {
            $username = normalize_username($_POST['username'] ?? '');
            $email = normalize_email($_POST['email'] ?? '');
            $password = (string)($_POST['password'] ?? '');
        
        // Validazione username/email con messaggio generico
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1");
        $stmt->execute([$username, $email]);
        
        if (mb_strlen($username, 'UTF-8') < 3) {
            $errors['username'] = "Min 3 caratteri";
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Email non valida";
        }
        if ($stmt->fetch()) {
            $errors['username'] = "Username o email non validi o già in uso";
            $securityLogger->log('register_duplicate', 'INFO', ['ip' => $_SERVER['REMOTE_ADDR']]);
        }
        
        $pwdEval = evaluatePasswordStrength($password);
        if (mb_strlen($password, 'UTF-8') < 12 || $pwdEval['score'] < 100 || !$pwdEval['complete']) {
            $errors['password'] = "Password richiede score 100/100 con tutte le categorie. " . $pwdEval['feedback'];
        }
        
        // Registrazione
        if (!array_filter($errors)) {
            try {
                $pdo->prepare("INSERT INTO users (username, email, password_hash, is_premium, is_admin, total_uploads, total_downloads_received, created_at) VALUES (?, ?, ?, 0, 0, 0, 0, NOW())")
                    ->execute([$username, $email, hash_password($password)]);
                
                log_security_event($pdo, 'USER_REGISTERED', 'INFO', (string)$pdo->lastInsertId(), ['username' => $username, 'password_strength' => $pwdEval['strength']]);
                
                $message = "Registrazione completata!";
                $messageType = 'success';
            } catch (Throwable $e) {
                $message = "Errore registrazione.";
            }
        } else {
            $message = "Correggi gli errori.";
        }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrazione</title>
    <link rel="stylesheet" href="assets/css/main.css">
    <link rel="stylesheet" href="assets/css/password-strength.css">
</head>
<body class="auth-page">
    <div class="auth-container">
        <h1>🎵 Crea Account</h1>
        
        <?php if($message):?>
            <p class="<?=$messageType==='success'?'message-success':'message-error'?>"><?=e($message)?></p>
        <?php endif;?>
        
        <?php if($messageType==='success'):?>
            <a href="login.php" class="btn-primary btn-link">Vai al Login</a>
        <?php else:?>
            <form method="POST" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?=e(generate_csrf_token())?>">
                
                <div class="form-group">
                    <label>Username *</label>
                    <input type="text" name="username" class="form-input <?=$errors['username']?'input-error':''?>" required minlength="3" maxlength="32" value="<?=e($_POST['username']??'')?>">
                    <?php if($errors['username']):?><div class="field-error">⚠ <?=e($errors['username'])?></div><?php endif;?>
                </div>

                <div class="form-group">
                    <label>Email *</label>
                    <input type="email" name="email" class="form-input <?=$errors['email']?'input-error':''?>" required maxlength="100" value="<?=e($_POST['email']??'')?>">
                    <?php if($errors['email']):?><div class="field-error">⚠ <?=e($errors['email'])?></div><?php endif;?>
                </div>

                <div class="form-group">
                    <label>Password *</label>
                    <input type="password" name="password" id="new_password" class="form-input" required minlength="12" maxlength="256">
                    <?php if($errors['password']):?><div class="field-error">⚠ <?=e($errors['password'])?></div><?php endif;?>
                    
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

                <button type="submit" id="submit-btn" class="btn-primary">Registrati</button>
            </form>
            <div class="text-center mt-20"><a href="login.php" class="link-secondary">← Torna al login</a></div>
        <?php endif;?>
    </div>

    <script src="assets/js/password-strength.js"></script>
</body>
</html>

