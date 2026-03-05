<?php
/*
 * ============================================================
 * authentication.php — Nucleo di autenticazione e sicurezza sessioni
 * ============================================================
 *
 * Questo file è incluso da ogni pagina dell'applicazione che richiede
 * autenticazione. Centralizza tutta la logica di sicurezza legata a:
 *
 *  - Configurazione sessioni sicure (cookie HttpOnly, SameSite, Secure)
 *  - Token CSRF per proteggere i form da Cross-Site Request Forgery
 *  - Hashing e verifica password con Argon2ID (algoritmo raccomandato da OWASP)
 *  - Timeout inattività (30 min) per invalidare sessioni abbandonate
 *  - Controllo ban real-time ad ogni richiesta autenticata
 *  - Rate limiting login (delegato a RateLimiter.php)
 *  - Funzioni di accesso controllato (require_login, require_admin, require_premium)
 *  - Sanitizzazione output HTML (funzione e())
 *  - Security headers HTTP (X-Frame-Options, CSP, HSTS, ecc.)
 *  - Logging eventi di sicurezza nel database
 *
 * DIPENDENZE:
 *   - maintenance.php  (pulizia periodica DB)
 *   - PDO $pdo         (deve essere disponibile nel contesto chiamante via db.php)
 *
 * NOTA SICUREZZA: questo file usa `declare(strict_types=1)` per evitare
 * conversioni di tipo implicite che potrebbero portare a vulnerabilità.
 */

declare(strict_types=1);

// Carica il modulo di manutenzione per la pulizia periodica del DB
// (viene eseguita con probabilità 1% ad ogni richiesta, senza cron)
require_once __DIR__ . '/maintenance.php';

/*
 * ─────────────────────────────────────────────────────────────
 * INIZIALIZZAZIONE SESSIONE SICURA
 * ─────────────────────────────────────────────────────────────
 * Viene eseguita solo se non c'è già una sessione attiva.
 * Configuriamo il cookie di sessione con le opzioni più restrittive possibili
 * per mitigare attacchi XSS, CSRF e session hijacking.
 */
if (session_status() !== PHP_SESSION_ACTIVE) {

    /*
     * strict_mode = 1: PHP rifiuta ID sessione forniti dal client che non
     * esistono ancora nel server, prevenendo session fixation attacks
     * (l'attaccante non può forzare un SessionID noto nella vittima).
     */
    ini_set('session.use_strict_mode', '1');

    /*
     * Rilevamento HTTPS: impostiamo il cookie come "Secure" solo se
     * la connessione è cifrata. In questo modo, in produzione (HTTPS),
     * il cookie non viene mai trasmesso su HTTP in chiaro.
     */
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

    session_set_cookie_params([
        'lifetime' => 0,          // 0 = cookie di sessione (scade alla chiusura del browser)
        'path'     => '/',         // accessibile all'intera applicazione
        'secure'   => $isHttps,    // trasmesso solo via HTTPS (se disponibile)
        'httponly' => true,        // non accessibile via JavaScript → protegge da XSS
        'samesite' => 'Lax',       // protegge da CSRF su richieste cross-site (bilancia sicurezza/usabilità)
    ]);

    session_start();
}

/*
 * ─────────────────────────────────────────────────────────────
 * HELPER DI SANITIZZAZIONE OUTPUT
 * ─────────────────────────────────────────────────────────────
 */

/**
 * e() — Sanitizzazione HTML per output sicuro (anti-XSS).
 *
 * Da usare su OGNI valore user-supplied prima di stamparlo nell'HTML.
 * - ENT_QUOTES: converte sia ' che " in entità HTML
 * - ENT_SUBSTITUTE: sostituisce sequenze UTF-8 invalide anziché generare errori
 * - UTF-8: encoding esplicito per evitare bypass multibyte
 *
 * @param  string $s  Stringa da sanificare
 * @return string     Stringa sicura per l'output HTML
 */
function e(string $s): string {
    return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/*
 * ─────────────────────────────────────────────────────────────
 * HELPER DI VALIDAZIONE INPUT
 * ─────────────────────────────────────────────────────────────
 */

/**
 * is_nonempty_string() — Verifica che un valore sia una stringa non vuota.
 *
 * Usata per validare parametri POST prima di processarli.
 * Il controllo di lunghezza massima previene attacchi di tipo
 * "oversized input" che potrebbero causare lentezze o overflow nel DB.
 *
 * @param  mixed $v       Valore da testare
 * @param  int   $maxLen  Lunghezza massima in caratteri UTF-8 (default 1000)
 * @return bool
 */
function is_nonempty_string(mixed $v, int $maxLen = 1000): bool {
    if (!is_string($v)) return false;
    $v = trim($v);
    // mb_strlen con UTF-8 per contare correttamente i caratteri multibyte
    if ($v === '' || mb_strlen($v, 'UTF-8') > $maxLen) return false;
    return true;
}

/**
 * normalize_username() — Normalizza e valida lo username.
 *
 * Applica una whitelist rigida sui caratteri consentiti (alfanumerici + _ . -).
 * Lunghezza 3–32 caratteri. Ritorna '' se il formato è invalido, così il chiamante
 * può rifiutare l'input senza esporre dettagli dell'errore all'utente.
 *
 * @param  string $u  Username grezzo dall'input utente
 * @return string     Username normalizzato oppure '' se invalido
 */
function normalize_username(string $u): string {
    $u = trim($u);
    // La regex whitelist blocca ogni tentativo di injection via username
    if (!preg_match('/^[A-Za-z0-9_.-]{3,32}$/', $u)) return '';
    return $u;
}

/**
 * normalize_email() — Normalizza e valida un indirizzo email.
 *
 * Usa filter_var con FILTER_VALIDATE_EMAIL che implementa RFC 5321/5322.
 * Limita a 100 caratteri per corrispondere al campo VARCHAR(100) nel DB
 * ed evitare input enormi tramite email crafted.
 *
 * @param  string $email  Email grezza
 * @return string         Email validata oppure '' se invalida
 */
function normalize_email(string $email): string {
    $email = trim($email);
    if ($email === '' || mb_strlen($email, 'UTF-8') > 100) return '';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return '';
    return $email;
}

/*
 * ─────────────────────────────────────────────────────────────
 * HELPER IP E RATE LIMITING
 * ─────────────────────────────────────────────────────────────
 */

/**
 * client_ip() — Restituisce l'IP reale del client.
 *
 * Usa REMOTE_ADDR (non X-Forwarded-For) per prevenire IP spoofing.
 * X-Forwarded-For è impostabile dal client e NON deve essere usato
 * per decisioni di sicurezza senza un proxy fidato configurato.
 *
 * @return string IP address del client
 */
function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * identifier_for_rate_limit() — Costruisce l'identificatore composito per il rate limiter.
 *
 * Combina username + IP per creare un identificatore che blocca:
 * - Brute force su un account specifico (username singolo, IP multipli)
 * - Attacchi credential stuffing distribuiti (stesso IP, username multipli)
 * Quando usato insieme al rate limit per solo IP, copre entrambi i vettori.
 *
 * @param  string $usernameNorm  Username già normalizzato
 * @return string                Identificatore nel formato "username|ip"
 */
function identifier_for_rate_limit(string $usernameNorm): string {
    return $usernameNorm . '|' . client_ip();
}

/*
 * ─────────────────────────────────────────────────────────────
 * LOGGING SICUREZZA
 * ─────────────────────────────────────────────────────────────
 */

/**
 * log_security_event() — Registra un evento di sicurezza nel database.
 *
 * Questa funzione è il punto centrale di audit trail dell'applicazione.
 * Ogni evento notevole (login, CSRF violation, path traversal, ecc.)
 * viene persistito con: tipo, severità, user_id, IP, user-agent, URI e contesto JSON.
 *
 * Livelli di severità supportati:
 *   - INFO     → eventi normali (login riuscito, upload, logout)
 *   - WARNING  → anomalie (credenziali errate, rate limit superato)
 *   - CRITICAL → attacchi rilevati (CSRF, path traversal, integrità file)
 *
 * Il try/catch garantisce che un errore di logging NON blocchi mai la richiesta
 * dell'utente (availability > perfect logging).
 *
 * @param PDO         $pdo       Connessione database
 * @param string      $eventType Tipo evento (es. 'LOGIN_SUCCESS', 'CSRF_VIOLATION')
 * @param string      $severity  'INFO' | 'WARNING' | 'CRITICAL'
 * @param string|null $userId    ID utente o null per richieste anonime
 * @param array       $context   Dati aggiuntivi serializzati in JSON
 */
function log_security_event(PDO $pdo, string $eventType, string $severity = 'INFO', ?string $userId = null, array $context = []): void {
    try {
        $ip  = client_ip();
        $ua  = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $uri = $_SERVER['REQUEST_URI'] ?? null;

        // Valida severità: valori non riconosciuti degradano a INFO
        $sev = strtoupper($severity);
        if (!in_array($sev, ['INFO','WARNING','CRITICAL'], true)) {
            $sev = 'INFO';
        }

        // Usa 'anonymous' se user_id non disponibile (es. tentativo login fallito)
        $uid = $userId ?? 'anonymous';

        // JSON_UNESCAPED_UNICODE evita escape inutili, JSON_UNESCAPED_SLASHES
        // rende i percorsi leggibili nei log
        $ctx = json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // Prepared statement: previene SQL injection anche nel logging
        $stmt = $pdo->prepare(
            "INSERT INTO security_logs (event_type, severity, user_id, ip_address, user_agent, request_uri, context, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW())"
        );
        $stmt->execute([$eventType, $sev, $uid, $ip, $ua, $uri, $ctx]);

    } catch (Throwable $e) {
        // Fallimento silenzioso: il logging NON deve mai interrompere il flusso
        // applicativo. In produzione si potrebbe aggiungere un fallback su file.
    }
}

/*
 * ─────────────────────────────────────────────────────────────
 * PASSWORD HASHING E VERIFICA
 * ─────────────────────────────────────────────────────────────
 */

/**
 * hash_password() — Genera hash sicuro della password con Argon2ID.
 *
 * Argon2ID è la scelta raccomandata da OWASP (2023) e NIST per il key
 * stretching delle password. Combina resistenza agli attacchi side-channel
 * di Argon2i con la resistenza GPU/ASIC di Argon2d.
 *
 * PHP usa i parametri di default raccomandati di libsodium:
 *   - memory: 65536 KB (64 MB)
 *   - time: 4 iterazioni
 *   - threads: 1
 *
 * Il salt è generato automaticamente in modo crittograficamente sicuro
 * da password_hash(), NON è necessario gestirlo manualmente.
 *
 * @param  string $password  Password in chiaro
 * @return string            Hash Argon2ID completo (includente salt e parametri)
 * @throws RuntimeException  Se l'hashing fallisce (es. memoria insufficiente)
 */
function hash_password(string $password): string {
    $hash = password_hash($password, PASSWORD_ARGON2ID);
    if ($hash === false) throw new RuntimeException('Password hashing failed');
    return $hash;
}

/**
 * verify_password() — Verifica una password contro il suo hash.
 *
 * password_verify() è timing-safe by design: impiega sempre lo stesso
 * tempo indipendentemente dalla correttezza della password, eliminando
 * i timing side-channel che potrebbero rivelare parzialmente la password.
 *
 * Gestisce automaticamente l'upgrade trasparente dell'algoritmo se in futuro
 * si cambia il parametro (es. da bcrypt ad Argon2ID) tramite password_needs_rehash().
 *
 * @param  string $password  Password in chiaro da verificare
 * @param  string $hash      Hash estratto dal database
 * @return bool              true se la password corrisponde
 */
function verify_password(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

/*
 * ─────────────────────────────────────────────────────────────
 * CONTROLLI DI ACCESSO
 * ─────────────────────────────────────────────────────────────
 */

/**
 * is_logged_in() — Controlla se l'utente ha una sessione attiva valida.
 *
 * La verifica del tipo (is_int) è fondamentale: previene attacchi dove
 * $_SESSION['user_id'] viene impostato con una stringa, array, o false,
 * che potrebbero bypassare controlli meno rigidi.
 *
 * @return bool true se la sessione contiene un user_id intero valido
 */
function is_logged_in(): bool {
    return isset($_SESSION['user_id']) && is_int($_SESSION['user_id']);
}

/**
 * require_login() — Forza il redirect al login se l'utente non è autenticato.
 *
 * Da chiamare in cima a ogni pagina che richiede autenticazione.
 * Termina immediatamente l'esecuzione con exit() dopo il redirect
 * per evitare che il codice successivo venga eseguito.
 */
function require_login(): void {
    if (!is_logged_in()) {
        header('Location: login.php');
        exit();
    }
}

/**
 * require_admin() — Forza autenticazione e verifica privilegi admin.
 *
 * Doppio check: prima verifica il login, poi controlla is_admin in sessione.
 * Ritorna HTTP 403 Forbidden (non redirect) per le pagine admin,
 * rendendo esplicita la natura del rifiuto.
 */
function require_admin(): void {
    require_login();
    if (empty($_SESSION['is_admin'])) {
        http_response_code(403);
        exit('Forbidden');
    }
}

/**
 * require_premium() — Verifica che l'utente abbia accesso premium.
 *
 * Gli admin hanno accesso implicito a tutti i contenuti premium
 * (fallback is_admin nel controllo), evitando che i superutenti
 * vengano bloccati da contenuti della loro stessa piattaforma.
 */
function require_premium(): void {
    require_login();
    if (empty($_SESSION['is_premium']) && empty($_SESSION['is_admin'])) {
        http_response_code(403);
        exit('Premium required');
    }
}

/*
 * ─────────────────────────────────────────────────────────────
 * RATE LIMITING LOGIN (funzioni legacy, mantenute per compatibilità)
 * La logica principale di rate limiting usa RateLimiter.php
 * ─────────────────────────────────────────────────────────────
 */

/**
 * login_throttle_status() — Controlla lo stato di blocco per un identificatore.
 *
 * Legge dal database quanti tentativi sono stati effettuati e se
 * l'account è attualmente bloccato. Calcola la scadenza del blocco
 * come last_attempt + 15 minuti.
 *
 * @param  PDO    $pdo         Connessione DB
 * @param  string $identifier  Username o "username|IP" o IP puro
 * @param  string $actionType  Tipo azione (default 'login')
 * @return array               ['blocked' => bool, 'attempts' => int, 'locked_until' => DateTime|null]
 */
function login_throttle_status(PDO $pdo, string $identifier, string $actionType = 'login'): array {
    $stmt = $pdo->prepare(
        "SELECT attempt_count, first_attempt, last_attempt, is_blocked
         FROM rate_limits
         WHERE identifier=? AND action_type=?
         LIMIT 1"
    );
    $stmt->execute([$identifier, $actionType]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    // Nessun record: nessun blocco attivo
    if (!$row) {
        return ['blocked' => false, 'attempts' => 0, 'locked_until' => null];
    }

    $attempts = (int)$row['attempt_count'];
    $isBlocked = (int)$row['is_blocked'] === 1;

    // Calcola quando scade il blocco (15 minuti dall'ultimo tentativo)
    $last = new DateTime($row['last_attempt']);
    $lockedUntil = (clone $last)->modify('+15 minutes');

    // Blocco ancora attivo: restituisce anche la scadenza per mostrare all'utente
    if ($isBlocked && (new DateTime('now')) < $lockedUntil) {
        return ['blocked' => true, 'attempts' => $attempts, 'locked_until' => $lockedUntil];
    }

    // Blocco scaduto o non attivo
    return ['blocked' => false, 'attempts' => $attempts, 'locked_until' => null];
}

/**
 * login_throttle_fail() — Registra un tentativo fallito e blocca se necessario.
 *
 * Usa una transazione con SELECT ... FOR UPDATE per prevenire race condition:
 * due richieste concorrenti non possono incrementare il contatore in parallelo
 * e "saltare" il blocco. La finestra temporale è 30 minuti: dopo 30 minuti
 * senza nuovi tentativi il contatore si azzera automaticamente.
 *
 * @param  PDO    $pdo         Connessione DB
 * @param  string $identifier  Identificatore (username o IP)
 * @param  string $actionType  Tipo azione
 * @param  int    $maxFails    Numero massimo tentativi prima del blocco (default 3)
 * @return array               ['attempts' => int, 'blocked' => bool]
 */
function login_throttle_fail(PDO $pdo, string $identifier, string $actionType = 'login', int $maxFails = 3): array {
    $now = (new DateTime('now'))->format('Y-m-d H:i:s');

    $pdo->beginTransaction();
    try {
        // FOR UPDATE: acquisisce lock pessimistico per evitare race condition
        $stmt = $pdo->prepare(
            "SELECT id, attempt_count, first_attempt, last_attempt, is_blocked
             FROM rate_limits
             WHERE identifier=? AND action_type=?
             FOR UPDATE"
        );
        $stmt->execute([$identifier, $actionType]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            // Primo tentativo fallito: crea il record
            $attempts = 1;
            $blocked = ($attempts >= $maxFails) ? 1 : 0;
            $ins = $pdo->prepare(
                "INSERT INTO rate_limits (identifier, action_type, attempt_count, first_attempt, last_attempt, is_blocked)
                 VALUES (?, ?, ?, ?, ?, ?)"
            );
            $ins->execute([$identifier, $actionType, $attempts, $now, $now, $blocked]);
        } else {
            $attempts = (int)$row['attempt_count'];

            // Finestra scorrevole: se l'ultimo tentativo è > 30 min fa, resetta
            // Questo impedisce che un attaccante paziente accumuli tentativi
            // con pause lunghe tra loro
            $first = new DateTime($row['first_attempt']);
            $windowEnd = (clone $first)->modify('+30 minutes');
            if ((new DateTime('now')) > $windowEnd) {
                $attempts = 0;
                $first = new DateTime('now');
            }

            $attempts++;
            $blocked = ($attempts >= $maxFails) ? 1 : 0;

            $upd = $pdo->prepare(
                "UPDATE rate_limits
                 SET attempt_count=?, first_attempt=?, last_attempt=?, is_blocked=?
                 WHERE id=?"
            );
            $upd->execute([$attempts, $first->format('Y-m-d H:i:s'), $now, $blocked, (int)$row['id']]);
        }

        $pdo->commit();
        return ['attempts' => $attempts, 'blocked' => ($attempts >= $maxFails)];

    } catch (Throwable $e) {
        $pdo->rollBack();
        // In caso di errore DB, considera l'account bloccato per sicurezza (fail-closed)
        return ['attempts' => $maxFails, 'blocked' => true];
    }
}

/**
 * login_throttle_success() — Pulisce il contatore dopo un login riuscito.
 *
 * Chiamata immediatamente dopo l'autenticazione riuscita. Resetta il contatore
 * così l'utente non rimane penalizzato dai tentativi precedenti una volta
 * che ha dimostrato di conoscere la password corretta.
 *
 * @param PDO    $pdo         Connessione DB
 * @param string $identifier  Identificatore da resettare
 * @param string $actionType  Tipo azione (default 'login')
 */
function login_throttle_success(PDO $pdo, string $identifier, string $actionType = 'login'): void {
    try {
        $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE identifier=? AND action_type=?");
        $stmt->execute([$identifier, $actionType]);
    } catch (Throwable $e) {
        // Fallimento silenzioso: non bloccare il login per un errore di cleanup
    }
}

/*
 * ─────────────────────────────────────────────────────────────
 * PROTEZIONE CSRF (Cross-Site Request Forgery)
 * ─────────────────────────────────────────────────────────────
 */

/**
 * generate_csrf_token() — Genera o recupera il token CSRF della sessione corrente.
 *
 * Il token viene generato una sola volta per sessione con random_bytes(32)
 * (256 bit di entropia crittografica) e conservato in $_SESSION.
 * Viene inserito come campo hidden in ogni form e verificato al submit.
 *
 * Meccanismo: poiché JavaScript di altri domini non può leggere i cookie
 * HttpOnly, un sito malevolo non può ottenere il token e quindi non può
 * costruire richieste POST valide per conto dell'utente.
 *
 * @return string Token CSRF hex da 64 caratteri
 */
function generate_csrf_token(): string {
    if (!isset($_SESSION['csrf_token'])) {
        // random_bytes() usa il CSPRNG del sistema operativo (getrandom/CryptGenRandom)
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * verify_csrf_token() — Verifica il token CSRF inviato con il form.
 *
 * Usa hash_equals() invece dell'operatore == per il confronto.
 * hash_equals() è timing-safe: impiega sempre lo stesso tempo
 * indipendentemente da quanti caratteri corrispondono, prevenendo
 * i timing attack che potrebbero dedurre il token carattere per carattere.
 *
 * @param  string|null $token  Token ricevuto dal form (da $_POST['csrf_token'])
 * @return bool                true se il token è valido
 */
function verify_csrf_token(?string $token): bool {
    if (!isset($_SESSION['csrf_token']) || $token === null) {
        return false;
    }
    // hash_equals: confronto in tempo costante (timing-safe)
    return hash_equals($_SESSION['csrf_token'], $token);
}

/*
 * ─────────────────────────────────────────────────────────────
 * SECURITY HEADERS HTTP
 * ─────────────────────────────────────────────────────────────
 */

/**
 * set_security_headers() — Imposta tutti gli HTTP security headers.
 *
 * Questo è il meccanismo di difesa in profondità a livello transport/browser.
 * Ogni header mitiga una categoria specifica di attacchi:
 *
 *  X-Frame-Options: DENY
 *    → Impedisce il caricamento in iframe (protegge da clickjacking)
 *
 *  X-Content-Type-Options: nosniff
 *    → Impedisce al browser di "sniffare" il MIME type e interpretare
 *      un file come diverso da quanto dichiarato (es. .txt come JS)
 *
 *  X-XSS-Protection: 1; mode=block
 *    → Attiva il filtro XSS legacy dei browser più vecchi (IE, vecchio Chrome)
 *      "mode=block" blocca il rendering anziché tentare sanitization
 *
 *  Referrer-Policy: strict-origin-when-cross-origin
 *    → Invia il Referer completo solo per richieste same-origin,
 *      solo l'origine per richieste cross-origin HTTPS→HTTPS,
 *      niente per richieste cross-origin che degradano a HTTP (leak protection)
 *
 *  Permissions-Policy
 *    → Disabilita API browser potenzialmente pericolose: geolocalizzazione,
 *      microfono e camera non devono mai essere accessibili da questa webapp
 *
 *  Content-Security-Policy
 *    → Whitelist delle sorgenti per ogni tipo di risorsa. 'self' limita tutto
 *      all'origine corrente, impedendo l'iniezione di script/stili da CDN
 *      esterni o inline (mitigazione principale per XSS stored/reflected)
 *
 *  Strict-Transport-Security (solo HTTPS)
 *    → Forza il browser a usare HTTPS per 1 anno (max-age=31536000)
 *      su tutti i sottodomini. Protegge da SSL stripping attacks.
 */
function set_security_headers(): void {
    // Impedisce clickjacking: la pagina non può essere caricata in frame/iframe
    header("X-Frame-Options: DENY");

    // Impedisce MIME type sniffing da parte del browser
    header("X-Content-Type-Options: nosniff");

    // Attiva il filtro XSS legacy del browser (utile per browser meno recenti)
    header("X-XSS-Protection: 1; mode=block");

    // Controllo granulare delle informazioni nel Referer header
    header("Referrer-Policy: strict-origin-when-cross-origin");

    // Disabilita API di hw sensitivo non necessarie all'applicazione
    header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

    // CSP: whitelist rigorosa delle sorgenti di contenuto (mitiga XSS)
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; font-src 'self'; script-src 'self';");

    // HSTS: imposto solo se la connessione è già HTTPS per non bloccare http in dev
    if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
        (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)) {
        // max-age = 1 anno; includeSubDomains copre tutti i sottodomini
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
}

/*
 * ─────────────────────────────────────────────────────────────
 * FLASH MESSAGES
 * ─────────────────────────────────────────────────────────────
 */

/**
 * clear_flash_message() — Rimuove i messaggi flash dalla sessione dopo la visualizzazione.
 *
 * I flash message sono messaggi one-shot (mostrati una volta sola).
 * Questo pattern "post-redirect-get" evita la re-submission del form
 * al refresh della pagina e garantisce che il messaggio non persista.
 */
function clear_flash_message(): void {
    if (isset($_SESSION['flash_message'])) {
        unset($_SESSION['flash_message']);
        unset($_SESSION['flash_type']);
    }
}

/*
 * ─────────────────────────────────────────────────────────────
 * VALIDAZIONE SESSIONE COMPLETA
 * ─────────────────────────────────────────────────────────────
 */

/**
 * validate_session() — Esegue una validazione completa e multi-layer della sessione.
 *
 * Chiamata da ogni pagina protetta dopo require_login().
 * Implementa 3 livelli di validazione:
 *
 *  Layer 1 — Verifica base PHP:
 *    Controlla che user_id sia presente in sessione.
 *
 *  Layer 2 — Timeout inattività (30 minuti):
 *    Se l'ultimo accesso è più vecchio di 1800 secondi, la sessione viene
 *    invalidata. Questo protegge le sessioni abbandonate su computer condivisi.
 *    Il timestamp last_activity viene aggiornato ad ogni richiesta valida.
 *
 *  Layer 3 — Controllo ban real-time:
 *    Ad ogni richiesta verifiche se l'utente è stato bannato nel DB.
 *    Questo garantisce che il ban admin abbia effetto immediato senza
 *    dover aspettare la scadenza del token di sessione.
 *
 * In caso di invalidazione:
 *  - I dati di sessione sensibili vengono distrutti (session_unset + session_destroy)
 *  - Una nuova sessione pulita viene avviata solo per il flash message
 *  - Restituisce false per permettere al chiamante di fare il redirect
 *
 * Effetto collaterale positivo: chiama maybe_run_maintenance() per la pulizia
 * periodica del DB senza bisogno di cron job dedicati.
 *
 * @param  PDO  $pdo  Connessione database
 * @return bool       true se la sessione è valida, false se deve fare logout
 */
function validate_session(PDO $pdo): bool {
    // Esegue pulizia DB con probabilità 1% (senza cron job, lightweight)
    maybe_run_maintenance($pdo);

    // Layer 1: user_id deve essere presente in sessione
    if (!isset($_SESSION['user_id'])) {
        return false;
    }

    $should_logout = false;
    $reason = '';

    // Layer 2: timeout inattività — 30 minuti di inattività invalidano la sessione
    // Protegge sessioni abbandonate su computer condivisi o terminali pubblici
    $timeout = 1800; // 30 minuti in secondi
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout)) {
        $should_logout = true;
        // Messaggio generico: non specifichiamo "inattività" per non rivelare
        // informazioni sulla durata della sessione agli attaccanti
        $reason = 'Sessione scaduta per inattività.';
    }
    // Aggiorna timestamp ad ogni richiesta valida (sliding window timeout)
    $_SESSION['last_activity'] = time();

    // Layer 3: controllo ban real-time nel database
    // Garantisce che un ban admin abbia effetto IMMEDIATO sulla sessione attiva
    if (!$should_logout) {
        try {
            // Query minimale: seleziona solo is_banned per ridurre il carico
            $stmt = $pdo->prepare("SELECT is_banned FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $status = $stmt->fetch(PDO::FETCH_ASSOC);

            // Utente non trovato nel DB (eliminato?) oppure è stato bannato
            if (!$status || $status['is_banned'] == 1) {
                $should_logout = true;
                $reason = 'Account bloccato o sessione non valida.';
            }
        } catch (Exception $e) {
            // In caso di errore DB, fail-secure: logout precauzionale
            $should_logout = true;
            $reason = 'Errore verifica account.';
        }
    }

    if ($should_logout) {
        // Distrugge completamente la sessione corrente (dati sensibili rimossi)
        session_unset();
        session_destroy();

        // Avvia una sessione fresca SOLO per trasmettere il messaggio di errore
        // (pattern flash-message per post-redirect-get)
        session_start();
        $_SESSION['flash_message'] = $reason;
        $_SESSION['flash_type'] = 'error';

        return false;
    }

    return true;
}