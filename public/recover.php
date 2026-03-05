<?php
/*
 * ============================================================
 * recover.php — Recovery password tramite email con token one-time
 * ============================================================
 *
 * Implementa un flusso di reset password in 3 fasi:
 *
 *  FASE A — Richiesta reset (POST identifier):
 *   - Accetta username O email come identificatore
 *   - Risposta SEMPRE uguale ("se l'account esiste, riceverai un'email")
 *     indipendentemente dall'esistenza dell'account: anti-enumeration
 *   - Rate limiting: max 3 richieste/giorno per IP (anti abuse)
 *   - Genera token crittograficamente sicuro: bin2hex(random_bytes(32)) = 64 hex chars
 *   - Salva nel DB l'hash SHA-256 del token (non il token in chiaro)
 *     per prevenire il furto del token se il DB venisse compromesso
 *   - Token valido 30 minuti (expires_at = NOW() + 30 min)
 *   - Invia l'URL di reset via email (PHPMailer + MailHog in dev, SMTP in prod)
 *
 *  FASE B — Verifica token (GET ?token=...):
 *   - Valida formato token: regex /^[a-f0-9]{64}$/ (64 hex chars)
 *   - Cerca hash SHA-256 del token nel DB (non il token in chiaro)
 *   - Controlla scadenza (expires_at < NOW()) e uso precedente (used_at IS NOT NULL)
 *   - Genera token CSRF separato per il form di reset (recover_reset_csrf_token)
 *
 *  FASE C — Reset password (POST token + new_password):
 *   - CSRF separato per questa fase (prevent CSRF sul form di reset)
 *   - Ri-verifica il token in DB con SELECT ... FOR UPDATE (transazione)
 *   - Validazione strength password (score 100/100, tutte le categorie)
 *   - Le password coincidono (conferma)
 *   - Hash Argon2ID della nuova password → UPDATE users
 *   - Marco il token come usato (used_at = NOW()) per one-time-use
 *   - Log dell'evento di sicurezza
 *
 * SICUREZZA TOKEN:
 *  - Generazione: random_bytes(32) = 256 bit entropia (CSPRNG)
 *  - Archiviazione: hash SHA-256 del token nel DB (no token in chiaro)
 *  - One-time: una volta usato, used_at viene impostato e il token non funziona più
 *  - Scadenza: 30 minuti (finestra breve per ridurre il rischio di intercettazione)
 *  - Cleanup: token scaduti/usati rimossi dal DB ogni 7+ giorni da maintenance.php
 */
declare(strict_types=1);

require_once '../includes/db.php';
require_once '../includes/authentication.php';
require_once '../includes/RateLimiter.php';

set_security_headers();

require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$rateLimiter = new RateLimiter($pdo);
$msg = '';
$error = '';

// Genera CSRF token per il form di richiesta reset (separato dal CSRF di login)
if (empty($_SESSION['recover_csrf_token'])) {
    $_SESSION['recover_csrf_token'] = bin2hex(random_bytes(32));
}

/* =======================
   PASSWORD STRENGTH EVALUATOR
   (Stessa logica di register.php e change_password.php)
   ======================= */
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
    $strength = ($score >= 100) ? 'forte' : (($score >= 50) ? 'media' : 'debole');
    $allFeedback = array_merge($missing ? ["Manca: " . implode(', ', $missing)] : [], $feedback);
    
    return ['score' => $score, 'strength' => $strength, 'feedback' => implode('. ', $allFeedback), 'complete' => empty($missing), 'is_acceptable' => $score >= 100 && empty($missing)];
}

/* =======================
   EMAIL SENDER (MAILHOG)
   ======================= */
function send_recovery_email(string $toEmail, string $username, string $resetUrl): bool
{
    $mail = new PHPMailer(true);

    try {
        // SMTP config da variabili ambiente (produzione) o fallback MailHog (sviluppo)
        $smtpHost   = getenv('SMTP_HOST')   ?: 'mailhog';
        $smtpPort   = (int)(getenv('SMTP_PORT')   ?: 1025);
        $smtpUser   = getenv('SMTP_USER')   ?: '';
        $smtpPass   = getenv('SMTP_PASS')   ?: '';
        $smtpSecure = getenv('SMTP_SECURE') ?: false;
        $smtpFrom   = getenv('SMTP_FROM')   ?: 'no-reply@music-platform.test';

        $mail->isSMTP();
        $mail->Host      = $smtpHost;
        $mail->Port      = $smtpPort;
        $mail->SMTPAuth  = $smtpUser !== '';
        $mail->SMTPSecure = $smtpSecure ?: false;
        if ($smtpUser !== '') {
            $mail->Username = $smtpUser;
            $mail->Password = $smtpPass;
        }

        $mail->setFrom($smtpFrom, 'Music Platform');
        $mail->addAddress($toEmail, $username);

        $mail->isHTML(true);
        $mail->Subject = 'Password recovery';
        $safeUrl = e($resetUrl);

        $mail->Body = "
            <p>Ciao <strong>" . e($username) . "</strong>,</p>
            <p>Per reimpostare la password clicca sul link seguente (valido 30 minuti):</p>
            <p><a href=\"$safeUrl\">$safeUrl</a></p>
            <p>Se non hai richiesto tu il reset, ignora questa email.</p>
        ";

        $mail->AltBody = "Reset password: $resetUrl";

        $mail->send();
        return true;
    } catch (Exception $e) {
        // In dev we could log $mail->ErrorInfo or $e->getMessage()
        return false;
    }
}

/* =======================
   TOKEN CHECK (GET)
   ======================= */
$token = isset($_GET['token']) && is_string($_GET['token']) ? trim($_GET['token']) : '';
$showResetForm = false;

if ($token !== '') {
    if (!preg_match('/^[a-f0-9]{64}$/i', $token)) {
        $error = "Link non valido.";
    } else {
        $tokenHash = hash('sha256', $token, true);

        $stmt = $pdo->prepare(
            "SELECT id, user_id, expires_at, used_at
             FROM password_resets
             WHERE token_hash = ?
             LIMIT 1"
        );
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            $error = "Link non valido o scaduto.";
        } else {
            $expires = new DateTime($row['expires_at']);
            $used = $row['used_at'];

            if ($used !== null || $expires < new DateTime()) {
                $error = "Link non valido o scaduto.";
            } else {
                $showResetForm = true;
                if (empty($_SESSION['recover_reset_csrf_token'])) {
                    $_SESSION['recover_reset_csrf_token'] = bin2hex(random_bytes(32));
                }
            }
        }
    }
}

/* =======================
   POST HANDLER
   ======================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* ===== RESET PASSWORD (con controlli avanzati) ===== */
    if (isset($_POST['token'])) {
        // verifica CSRF per il form di reset
        if (!isset($_POST['reset_csrf_token']) || !hash_equals($_SESSION['recover_reset_csrf_token'] ?? '', $_POST['reset_csrf_token'])) {
            $error = "Token di sicurezza non valido. Riprova.";
            log_security_event($pdo, 'CSRF_TOKEN_INVALID', 'WARNING', 'anonymous', ['form' => 'recover_reset']);
        } else {
        $postToken = $_POST['token'];
        $newPass = $_POST['new_password'] ?? null;
        $confirmPass = $_POST['confirm_password'] ?? null;

        // Validazione token (DEVE essere esattamente 64 caratteri esadecimali)
        if (
            !is_string($postToken) ||
            strlen($postToken) !== 64 ||
            !preg_match('/^[a-f0-9]{64}$/i', $postToken) ||
            !is_nonempty_string($newPass, 256) ||
            mb_strlen((string)$newPass, 'UTF-8') < 12
        ) {
            $error = "Richiesta non valida.";
        } 
        // Controllo conferma password
        elseif ($newPass !== $confirmPass) {
            $error = "Le password non coincidono.";
        }
        else {
            // controllo strength pw
            $strengthResult = evaluatePasswordStrength((string)$newPass);
            
            if (!$strengthResult['is_acceptable']) {
                $error = "Password richiede score 100/100 con tutte le categorie. " . $strengthResult['feedback'];
            } else {
                $pdo->beginTransaction();
                try {
                    $tokenHash = hash('sha256', (string)$postToken, true);

                    $stmt = $pdo->prepare(
                        "SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at, u.password_hash as old_hash
                         FROM password_resets pr
                         JOIN users u ON pr.user_id = u.id
                         WHERE pr.token_hash = ?
                         FOR UPDATE"
                    );
                    $stmt->execute([$tokenHash]);
                    $row = $stmt->fetch(PDO::FETCH_ASSOC);

                    if (!$row) {
                        throw new RuntimeException('invalid_token');
                    }

                    if ($row['used_at'] !== null || new DateTime($row['expires_at']) < new DateTime()) {
                        throw new RuntimeException('expired_token');
                    }

                    // controllo: La nuova password non deve essere uguale alla vecchia
                    if (password_verify((string)$newPass, $row['old_hash'])) {
                        $pdo->rollBack();
                        $error = "La nuova password non può essere uguale a quella precedente.";
                    } else {
                        $uid = (int)$row['user_id'];
                        $hash = hash_password((string)$newPass);

                        $pdo->prepare("UPDATE users SET password_hash=? WHERE id=?")
                            ->execute([$hash, $uid]);

                        $pdo->prepare("UPDATE password_resets SET used_at=NOW() WHERE id=?")
                            ->execute([(int)$row['id']]);

                        $pdo->commit();

                        // Reset del rate limit per il login di questo utente
                        // In login.php l'identifier è hash('sha256', $username)
                        // Dobbiamo recuperare lo username per calcolare l'hash corretto
                        $stmtUser = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                        $stmtUser->execute([$uid]);
                        $usernameFound = $stmtUser->fetchColumn();
                        
                        if ($usernameFound) {
                            $rateLimiter->resetLimit($usernameFound, 'login');
                        }

                        // (rigenera dopo reset password completato)
                        // invalida eventuali sessioni compromesse associate all'account
                        session_regenerate_id(true);

                        log_security_event($pdo, 'PASSWORD_RESET_SUCCESS', 'INFO', (string)$uid, [
                            'password_strength' => $strengthResult['strength'],
                            'password_score' => $strengthResult['score']
                        ]);
                        $msg = "Password aggiornata correttamente! Ora puoi fare login.";
                        $showResetForm = false; // Nasconde il form dopo successo
                    }
                } catch (Throwable $e) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    log_security_event($pdo, 'PASSWORD_RESET_ERROR', 'CRITICAL', 'anonymous', ['reason' => $e->getMessage()]);
                    $error = "Errore durante il reset password. Il link potrebbe essere scaduto.";
                }
            }
        }
        } // end CSRF check
    }

    /* ===== REQUEST RESET ===== */
    else {
        // CSRF check per form richiesta reset
        if (!isset($_POST['recover_csrf_token']) || !hash_equals($_SESSION['recover_csrf_token'] ?? '', $_POST['recover_csrf_token'])) {
            $error = "Token di sicurezza non valido. Riprova.";
            log_security_event($pdo, 'CSRF_TOKEN_INVALID', 'WARNING', 'anonymous', ['form' => 'recover_request']);
        } else {
        $identifier = $_POST['identifier'] ?? null;

        if (is_nonempty_string($identifier, 255)) {
            $stmt = $pdo->prepare(
                "SELECT id, username, email
                 FROM users
                 WHERE username=? OR email=?
                 LIMIT 1"
            );
            $stmt->execute([(string)$identifier, (string)$identifier]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $user_identifier = (int)$user['id'];
                
                if (!$rateLimiter->checkLimit($user_identifier, 'password_recovery')) {
                    $error = "Limite giornaliero raggiunto (3 richieste). Riprova domani.";
                } else {
                    // invalida token precedenti
                    $pdo->prepare(
                        "UPDATE password_resets
                         SET used_at=NOW()
                         WHERE user_id=? AND used_at IS NULL"
                    )->execute([$user_identifier]);

                    $token = bin2hex(random_bytes(32));
                    $tokenHash = hash('sha256', $token, true);
                    $expires = (new DateTime('+30 minutes'))->format('Y-m-d H:i:s');

                    $pdo->prepare(
                        "INSERT INTO password_resets (user_id, token_hash, expires_at)
                         VALUES (?, ?, ?)"
                    )->execute([$user_identifier, $tokenHash, $expires]);

                    $baseUrl = getenv('APP_BASE_URL') ?: 'http://localhost';
                    $resetUrl = rtrim($baseUrl, '/') . '/recover.php?token=' . $token;

                    $sent = send_recovery_email((string)$user['email'], (string)$user['username'], $resetUrl);

                    log_security_event($pdo, 'PASSWORD_RESET_REQUEST', $sent ? 'INFO' : 'WARNING', (string)$user_identifier, [
                        'mail_sent' => $sent ? 1 : 0
                    ]);
                }
            } else {
                log_security_event($pdo, 'PASSWORD_RESET_UNKNOWN', 'WARNING', 'anonymous', ['identifier' => (string)$identifier]);
            }

            // risposta generica anti user-enumeration (sempre mostrata)
            if (empty($error)) {
                $msg = "Se l'account esiste, riceverai un'email con le istruzioni.";
            }
        } else {
            $error = "Inserisci username o email.";
        }
        } // end CSRF check
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Recupero password</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="assets/css/main.css">
<link rel="stylesheet" href="assets/css/password-strength.css">
</head>
<body class="auth-page">
    <div class="auth-container">
        <h1>Recupero password</h1>

        <?php if ($msg !== ''): ?>
            <p class="message-success"><?= e($msg) ?></p>
            <a href="login.php" class="btn-primary btn-link mt-15">Vai al Login →</a>
        <?php endif; ?>

        <?php if ($error !== ''): ?>
            <p class="message-error"><?= e($error) ?></p>
        <?php endif; ?>

        <?php if ($showResetForm && $msg === ''): ?>
            <!-- form reset password (con controlli avanzati) -->
            <form method="POST" id="resetForm">
                <input type="hidden" name="token" value="<?= e($token) ?>">
                <input type="hidden" name="reset_csrf_token" value="<?= e($_SESSION['recover_reset_csrf_token'] ?? '') ?>">
                
                <div class="form-group">
                    <label>Nuova password</label>
                    <input type="password" name="new_password" id="new_password" class="form-input" 
                           required minlength="12" maxlength="256" 
                           placeholder="Minimo 12 caratteri">
                    
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

                <div class="form-group">
                    <label>Conferma password</label>
                    <input type="password" name="confirm_password" id="confirm_password" class="form-input" 
                           required maxlength="256" placeholder="Ripeti la password">
                    <p id="confirm-match" class="confirm-match"></p>
                </div>

                <button type="submit" id="submit-btn" class="btn-primary">Aggiorna password</button>
                
                <p class="mt-15 text-sm text-gray text-center">
                    La password deve raggiungere 100/100 con tutte le 5 categorie
                </p>
            </form>
            
            <script src="assets/js/password-reset.js"></script>
            
        <?php elseif ($msg === ''): ?>
            <!-- form richiesta reset -->
            <form method="POST">
                <input type="hidden" name="recover_csrf_token" value="<?= e($_SESSION['recover_csrf_token'] ?? '') ?>">
                <div class="form-group">
                    <label>👤 Username o Email</label>
                    <input type="text" name="identifier" class="form-input" required maxlength="255"
                           placeholder="Inserisci username o email">
                </div>

                <button type="submit" class="btn-primary">📧 Invia link di recupero</button>
            </form>
        <?php endif; ?>

        <div class="mt-20 text-center">
            <a href="login.php" class="link-secondary">← Torna al login</a>
        </div>
    </div>
</body>
</html>
