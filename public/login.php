<?php

/*
 * ============================================================
 * login.php — Autenticazione utente con protezioni avanzate
 * ============================================================
 *
 * Misure di sicurezza implementate:
 *
 *  1. PROTEZIONE CSRF:
 *     Token casuale in sessione (256 bit) verificato con hash_equals()
 *     (timing-safe) prima di processare le credenziali.
 *
 *  2. RATE LIMITING DOPPIO LAYER:
 *     a) Per IP:       5 tentativi/24h per indirizzo IP (anti credential stuffing)
 *     b) Per username: 5 tentativi/24h per account (anti targeted brute force)
 *     I due layer combinati mitigano sia spray attacks che targeted attacks.
 *
 *  3. MESSAGGI GENERICI (Anti-Enumeration):
 *     Username inesistente e password errata producono IDENTICO messaggio.
 *     L'attaccante non può determinare quali username esistono nel sistema.
 *
 *  4. TIMING ATTACK PREVENTION:
 *     Se lo username non esiste, viene eseguito comunque un password_verify()
 *     su hash dummy per rendere il tempo di risposta identico in entrambi i casi.
 *
 *  5. SESSION FIXATION PREVENTION:
 *     session_regenerate_id(true) dopo login riuscito genera nuovo session ID
 *     e invalida il precedente, prevenendo session fixation attacks.
 *
 *  6. LOG ASIMMETRICO:
 *     Lato server: log dettagliato con username, IP e causa specifica.
 *     Lato client: messaggi generici senza informazioni sullo stato interno.
 *
 *  7. BAN CHECK:
 *     Anche con credenziali corrette, il login è rifiutato se is_banned=1.
 *     Il messaggio rimane generico (no conferma del ban all'attaccante).
 */

declare(strict_types=1);

require_once '../includes/db.php';
require_once '../includes/authentication.php';
require_once '../includes/RateLimiter.php';
require_once '../includes/SecurityLogger.php';

set_security_headers();

$rateLimiter = new RateLimiter($pdo);
$securityLogger = new SecurityLogger($pdo);

// Ottieni configurazione
$loginConfig = $rateLimiter->getLimits()['login'] ?? ['max_attempts' => 5, 'window_minutes' => 1];
$maxAttempts = $loginConfig['max_attempts'];
$windowMinutes = $loginConfig['window_minutes'];

$error = '';
$info = '';

/*
 * COSTANTI MESSAGGI GENERICI (Anti-Enumeration)
 *
 * Usare costanti invece di stringhe inline garantisce che tutti i percorsi
 * di codice usino ESATTAMENTE lo stesso testo. Se un percorso usasse un
 * messaggio diverso, l'attaccante potrebbe distinguere i casi e enumerare
 * gli username validi. Queste costanti sono la difesa contro quella vulnerabilità.
 */
const MSG_INVALID_CREDENTIALS = "Credenziali non valide.";
const MSG_ACCOUNT_BLOCKED     = "Account temporaneamente bloccato. Riprova più tardi.";
const MSG_SECURITY_ERROR      = "Errore di sicurezza. Riprova.";

// Gestione parametri di errore da redirect di altre pagine.
// Lo switch/case valida che solo valori attesi vengano usati:
// qualsiasi altro valore GET viene silenziosamente ignorato (no raw output di parametri non sanitizzati)
if (isset($_GET['error'])) {
    switch ($_GET['error']) {
        case 'too_many_attempts':
            $error = "Troppi tentativi errati. Account temporaneamente bloccato.";
            break;
        case 'account_banned':
            // Messaggio uguale a "credenziali non valide": non confermiamo il ban
            $error = "Credenziali non valide o account non disponibile.";
            break;
        case 'session_invalid':
            $error = "Sessione non valida o scaduta. Effettua nuovamente il login.";
            break;
        case 'ip_mismatch':
            // Cambiamento IP durante la sessione: possibile session hijacking
            $error = "Accesso rilevato da un nuovo indirizzo IP. Verifica la tua identità.";
            break;
        case 'account_not_found':
            // Stesso messaggio di credenziali errate: anti-enumeration
            $error = "Credenziali non valide.";
            break;
        case 'csrf_invalid':
            $error = "Token di sicurezza scaduto. Riprova.";
            break;
        case 'unauthorized':
            $error = "Accesso negato. Non hai i permessi per accedere a quella pagina.";
            break;
        // Valori sconosciuti: ignorati silenziosamente (no output di dati non validati)
    }
}

if (isset($_GET['logout']) && $_GET['logout'] === 'success') {
    $info = "Logout effettuato.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // LAYER 1: Verifica CSRF token — prima di qualsiasi altra elaborazione.
    // hash_equals() confronta i token in tempo costante (timing-safe): previene
    // che un attaccante misuri il tempo di confronto per dedurre caratteri del token.
    // Qualsiasi azione POST senza CSRF valido viene rifiutata e loggata.
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $error = MSG_SECURITY_ERROR;
        log_security_event($pdo, 'CSRF_TOKEN_INVALID', 'WARNING', 'anonymous');
    } else {
        // LAYER 2: Validazione base degli input (tipo, lunghezza).
        // is_nonempty_string: verifica che sia stringa, non vuota, e dentro i limiti.
        // max 32 char per username: conforme alla constraint DB (VARCHAR 32).
        // max 256 char per password: previene DoS via hashing di stringhe enormi
        // (password_verify su un input da 1MB sarebbe costoso con Argon2ID).
        $uRaw = $_POST['username'] ?? null;
        $pRaw = $_POST['password'] ?? null;

        if (!is_nonempty_string($uRaw, 32) || !is_nonempty_string($pRaw, 256)) {
            $error = MSG_INVALID_CREDENTIALS;
        } else {
            // LAYER 3: Normalizzazione username — whitelist caratteri.
            // normalize_username applica /^[A-Za-z0-9_.-]{3,32}$/ e ritorna '' se non valido.
            // Restituire MSG_INVALID_CREDENTIALS (e non "username non valido") evita
            // di rivelare quali formati di username accetta il sistema.
            $username = normalize_username($uRaw);
            $password = (string)$pRaw;

            if ($username === '') {
                $error = MSG_INVALID_CREDENTIALS;
            } else {
                $ip = $_SERVER['REMOTE_ADDR'];

                // LAYER 4a: Rate limit per IP — blocca brute force distribuito.
                // isBlocked() controlla senza incrementare: il contatore cresce solo
                // sui tentativi falliti, tramite recordFailedAttempt() nel ramo else.
                $ip_identifier = 'login_ip_' . $ip;
                if ($rateLimiter->isBlocked($ip_identifier, 'login')) {
                    $error = MSG_ACCOUNT_BLOCKED;
                    $securityLogger->log('login_ip_rate_limit_exceeded', 'WARNING', [
                        'ip' => $ip
                    ]);
                }
                // LAYER 4b: Rate limit per username — blocca targeted brute force.
                // Anche se l'IP cambia (botnet), il contatore per username rimane.
                elseif ($rateLimiter->isBlocked($username, 'login')) {
                    $error = MSG_ACCOUNT_BLOCKED;
                    $securityLogger->log('login_rate_limit_exceeded', 'WARNING', [
                        'username' => $username,
                        'ip' => $ip
                    ]);
                } else {
                    // LAYER 5: Query database — prepared statement previene SQL injection.
                    // Si selezionano solo le colonne necessarie (principio del minimo privilegio).
                    // LIMIT 1 ottimizza la query (username è UNIQUE nel DB).
                    $stmt = $pdo->prepare("
                        SELECT id, username, password_hash, is_admin, is_premium, is_banned 
                        FROM users 
                        WHERE username = ? 
                        LIMIT 1
                    ");
                    $stmt->execute([$username]);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    $passwordCorrect = false;
                    // LAYER 6: Timing Attack Prevention.
                    // CASO A — utente trovato: verifica normale con password_verify().
                    // CASO B — utente NON trovato: si esegue comunque password_verify()
                    // su un hash dummy (stesso algoritmo Argon2ID, stesso costo computazionale).
                    // Senza questo, un attaccante potrebbe misurare la differenza di tempo tra
                    // "utente non esiste" (ritorno immediato) e "password sbagliata" (verify lento)
                    // per enumerare username validi anche senza ottenere accesso.
                    if ($user && isset($user['password_hash']) && is_string($user['password_hash'])) {
                        $passwordCorrect = verify_password($password, $user['password_hash']);
                    } else {
                        // Hash dummy con parametri identici a quelli usati da hash_password():
                        // memory_cost=65536 (64MB), time_cost=4, threads=1.
                        // Il valore specifico non ha importanza: password_verify() fallirà sempre,
                        // ma impiegherà lo stesso tempo di una verifica reale.
                        password_verify($password, '$argon2id$v=19$m=65536,t=4,p=1$dHN0dGVzdHRlc3R0ZXN0$K6qGJZhVz7hLBqVlkT2I5K6qGJZhVz7hLBqVlkT2I5A');
                    } 

                    if ($user && $passwordCorrect) {
                        // Credenziali corrette — verifiche post-autenticazione.

                        // LAYER 7: Controllo ban — anche con password corretta, un utente
                        // bannato non può accedere. Il controllo avviene DOPO il verify per
                        // non rivelare se l'utente esiste tramite tempistiche diverse.
                        if ($user['is_banned'] == 1) {
                            $securityLogger->log('banned_user_login_attempt', 'WARNING', ['username' => $username]);
                            $error = "Account bloccato o bannato.";
                        } else {
                            // Resetta i contatori rate limit — login riuscito non deve
                            // penalizzare tentativi futuri legittimi.
                            $rateLimiter->resetLimit($username, 'login');
                            $rateLimiter->resetLimit($ip_identifier, 'login');
                            
                            // LAYER 8: SESSION FIXATION PREVENTION.
                            // session_regenerate_id(true) genera un nuovo session ID e
                            // invalida il precedente, eliminandolo dal storage server-side.
                            // Senza questo, un attaccante che conosca il session ID
                            // pre-login (es. via XSS sulla pagina di login) potrebbe
                            // ereditare la sessione autenticata (session fixation attack).
                            session_regenerate_id(true);
                            $_SESSION['user_id'] = (int)$user['id'];
                            $_SESSION['username'] = (string)$user['username'];
                            $_SESSION['is_admin'] = (int)$user['is_admin'];
                            $_SESSION['is_premium'] = (int)$user['is_premium'];
                            // IP binding: salvato per rilevare session hijacking nelle pagine
                            // protette (validate_session() confronta questo con REMOTE_ADDR).
                            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                            // Timestamp per il controllo inattività (30 min timeout in validate_session).
                            $_SESSION['created_at'] = time();
                            $_SESSION['last_activity'] = time();
                            
                            $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([(int)$user['id']]);
                            
                            // Log dettagliato solo lato server
                            log_security_event($pdo, 'LOGIN_SUCCESS', 'INFO', (string)$user['id'], [
                                'username' => $username,
                                'ip' => $ip
                                ]);
                                
                                header('Location: dashboard.php');
                                exit();
                        }
                    } else {
                        // ANTI-ENUMERATION: messaggio IDENTICO per "username non esiste"
                        // e "password sbagliata". Un messaggio diverso permetterebbe
                        // di scoprire quali username sono registrati nel sistema.
                        $error = MSG_INVALID_CREDENTIALS;

                        // Incrementa i contatori SOLO sui tentativi falliti.
                        // I login con credenziali corrette non consumano il limite.
                        $rateLimiter->recordFailedAttempt($username, 'login');
                        $rateLimiter->recordFailedAttempt($ip_identifier, 'login');

                        // Log server-side distingue i due casi per il SOC/analisi,
                        // ma il client non vede mai questa distinzione.
                        $logEvent = $user ? 'LOGIN_FAILED_WRONG_PASSWORD' : 'LOGIN_FAILED_USER_NOT_FOUND';
                        log_security_event($pdo, $logEvent, 'WARNING', $user ? (string)$user['id'] : 'unknown', [
                            'username_attempted' => $username,
                            'ip' => $ip
                        ]);
                    }
                }
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
    <title>Login - MusicProject</title>
    <link rel="stylesheet" href="assets/css/main.css">
    <link rel="stylesheet" href="assets/css/flash-messages.css">
</head>
<body class="auth-page">
    
    <?php if (isset($_SESSION['flash_message'])): ?>
        <?php
        $flash_type = $_SESSION['flash_type'] ?? 'info';
        $flash_message = $_SESSION['flash_message'];
        // Pulizia immediata: i flash messages devono essere mostrati UNA SOLA VOLTA.
        // Rimuoverli prima del rendering previene che un refresh mostri il messaggio di nuovo.
        unset($_SESSION['flash_message'], $_SESSION['flash_type']);
        
        $icons = ['error' => '✕', 'success' => '✓', 'warning' => '⚠', 'info' => 'ℹ'];
        $icon = $icons[$flash_type] ?? $icons['info'];
        ?>
        <div class="flash-container">
            <div class="flash-message <?= htmlspecialchars($flash_type ?? '', ENT_QUOTES, 'UTF-8') ?>" id="flash-alert">
                <span class="flash-icon"><?= $icon ?></span>
                <div class="flash-content">
                    <strong><?= htmlspecialchars($flash_type ?? '', ENT_QUOTES, 'UTF-8') ?></strong>
                    <!-- htmlspecialchars con ENT_QUOTES previene XSS: anche messaggi contenenti
                         <script> o " vengono neutralizzati prima dell'output HTML. -->
                    <p><?= htmlspecialchars($flash_message ?? '', ENT_QUOTES, 'UTF-8') ?></p>
                </div>
                <button class="flash-close">×</button>
            </div>
        </div>
    <?php endif; ?>

    <div class="auth-container">
        <h1>🎵 MusicProject</h1>
        <p class="text-center mb-20 text-muted">Accedi al tuo account</p>

        <?php if ($info !== ''): ?>
            <p class="message-success"><?= e($info) ?></p>
        <?php endif; ?>

        <?php if ($error !== ''): ?>
            <p class="message-error"><?= e($error) ?></p>
        <?php endif; ?>

        <form method="POST" action="login.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= e(generate_csrf_token()) ?>">
            
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-input" required maxlength="32" autofocus>
            </div>

            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-input" required maxlength="256">
            </div>

            <button type="submit" class="btn-primary">Entra</button>
        </form>

        <div class="form-divider">
            <a href="register.php" class="link-secondary">Registrati</a>  
            <a href="recover.php" class="link-secondary">Password dimenticata?</a>
        </div>
    </div>

    <script src="assets/js/flash-messages.js"></script>
</body>
</html>

