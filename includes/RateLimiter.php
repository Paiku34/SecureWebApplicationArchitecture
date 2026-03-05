<?php
/*
 * ============================================================
 * RateLimiter.php — Protezione brute force e abuse per azioni sensibili
 * ============================================================
 *
 * Questa classe implementa un sistema di rate limiting persistente su DB
 * per tutte le azioni critiche dell'applicazione (login, upload, download, ecc.).
 *
 * PRINCIPIO DI FUNZIONAMENTO:
 *  Ogni coppia (identifier, action_type) ha un contatore nel DB.
 *  Per azioni con esito binario (login, cambio password) usare:
 *   - isBlocked()            → controlla solo, NON incrementa
 *   - recordFailedAttempt()  → incrementa SOLO se l'azione è fallita
 *   - resetLimit()           → azzera dopo un'azione riuscita
 *  Per azioni che vanno sempre conteggiate (upload, download, view):
 *   - checkLimit()           → controlla E incrementa in un'unica chiamata
 *
 * MOTIVAZIONE DATABASE vs. MEMORIA:
 *  Usare il DB (invece di Redis o APCu) garantisce che il rate limiting
 *  funzioni correttamente in scenari multi-processo e riavvii del server,
 *  senza richiedere infrastruttura aggiuntiva.
 *
 * IDENTIFICATORI USATI:
 *  - login:             username (per attacchi mirati su account)
 *  - login:             'login_ip_' . $ip (per attacchi distribuiti per IP)
 *  - register:          'register_ip_' . $ip
 *  - upload/download:   'user_' . $user_id
 *  - password_change:   $user_id (numerico)
 *  - password_recovery: username o email
 *
 * ANTI-RACE CONDITION:
 *  incrementAttempt() usa INSERT ON DUPLICATE KEY UPDATE che è atomico in MySQL:
 *  anche con richieste concorrenti, il contatore viene incrementato correttamente.
 *
 * SICUREZZA:
 *  - Il blocco dura il doppio della finestra (window_minutes * 2)
 *  - Admin può sbloccare manualmente via forceUnblock()
 *  - Tutti gli eventi vengono loggati tramite SecurityLogger
 *  - Pulizia automatica dei record vecchi (>24h) tramite cleanup()
 */

class RateLimiter {

    /** @var PDO Connessione al database */
    private $pdo;

    /** @var SecurityLogger Logger per eventi di sicurezza */
    private $securityLogger;

    /**
     * Configurazione dei limiti per tipo di azione.
     *
     * Ogni entry definisce:
     *  max_attempts    → numero massimo di tentativi nella finestra
     *  window_minutes  → durata della finestra temporale in minuti
     *
     * Il blocco dura window_minutes * 2 (doppia penalità per chi supera il limite).
     *
     * RAGIONAMENTO DEI VALORI:
     *  login (5/24h):            Max 5 login errati al giorno per account,
     *                             sufficiente per utenti legittimi che dimenticano la password
     *  register (5/h):           Limita account farming automatizzato per IP
     *  upload (10/h):            Previene flooding dello storage
     *  download (10/h):          Previene scraping massivo dei contenuti
     *  view (1000/h):            Limite alto: solo per bloccare bot aggressivi
     *  password_change (3/24h):  Pochissimi tentativi: azione rarissima per utenti legittimi
     *  password_recovery (3/24h): Limita enumeration via reset password
     *
     * @var array<string, array{max_attempts: int, window_minutes: int}>
     */
    private $limits = [
        'login'             => ['max_attempts' => 5,    'window_minutes' => 1440], // 5 tentativi in 24h
        'register'          => ['max_attempts' => 5,    'window_minutes' => 60],   // 5 registrazioni/ora per IP
        'upload'            => ['max_attempts' => 10,   'window_minutes' => 60],   // 10 upload/ora per utente
        'download'          => ['max_attempts' => 10,   'window_minutes' => 60],   // 10 download/ora per utente
        'view'              => ['max_attempts' => 1000, 'window_minutes' => 60],   // 1000 visualizzazioni/ora
        'password_change'   => ['max_attempts' => 3,    'window_minutes' => 1440], // 3 cambi password/giorno
        'password_recovery' => ['max_attempts' => 3,    'window_minutes' => 1440], // 3 reset password/giorno
    ];

    /**
     * Costruttore: inizializza PDO e SecurityLogger.
     *
     * @param PDO $pdo  Connessione database iniettata dall'esterno
     */
    public function __construct($pdo) {
        $this->pdo = $pdo;

        // SecurityLogger viene istanziato qui per non richiederlo come dipendenza esterna
        require_once __DIR__ . '/SecurityLogger.php';
        $this->securityLogger = new SecurityLogger($pdo);
    }

    /**
     * checkLimit() — Punto di ingresso principale del rate limiter.
     *
     * Verifica se l'azione è permessa per questo identifier e, in caso
     * positivo, incrementa il contatore. In caso negativo, blocca e logga.
     *
     * FLUSSO DECISIONALE:
     *  1. action_type sconosciuto → false (sicurezza per default)
     *  2. Nessun record → primo tentativo, permesso → incrementa
     *  3. Record con finestra scaduta → resetta e permetti
     *  4. Limite aumentato nel config → sblocca chi era bloccato col vecchio limite
     *  5. Ancora bloccato e ban non scaduto → false
     *  6. Ban scaduto → resetta e permetti
     *  7. Contatore >= limite → blocca → false
     *  8. Sotto il limite → incrementa → true
     *
     * @param  string $identifier   Identificatore univoco (IP, username, user_id, ecc.)
     * @param  string $action_type  Tipo di azione (deve essere in $this->limits)
     * @return bool                 true = azione permessa, false = bloccata
     */
    public function checkLimit($identifier, $action_type) {

        // Caso 1: tipo azione non configurato → sicurezza per default (blocca + log)
        if (!isset($this->limits[$action_type])) {
            error_log("Invalid action_type: $action_type");
            $this->securityLogger->log('invalid_action_type', 'WARNING', [
                'action_type' => $action_type,
                'identifier'  => $identifier
            ]);
            return false;
        }

        $config = $this->limits[$action_type];

        // Calcola l'inizio della finestra temporale corrente
        // Tutto ciò che ha last_attempt < window_start è "vecchio" e ignorato
        $window_start = date('Y-m-d H:i:s', strtotime("-{$config['window_minutes']} minutes"));

        // Legge lo stato corrente dal DB per questo identifier+action_type
        $stmt = $this->pdo->prepare("
            SELECT attempt_count, is_blocked, first_attempt, last_attempt
            FROM rate_limits
            WHERE identifier = ? AND action_type = ?
        ");
        $stmt->execute([$identifier, $action_type]);
        $record = $stmt->fetch();

        // Caso 2: nessun record → primo tentativo → crea il record e permetti
        if (!$record) {
            $this->incrementAttempt($identifier, $action_type, $window_start);
            return true;
        }

        // Caso 3: finestra temporale scaduta → il record è "vecchio" → resetta tutto
        // (l'utente non deve essere penalizzato per tentativi molto vecchi)
        if ($record['last_attempt'] < $window_start) {
            $this->resetLimit($identifier, $action_type);
            error_log("RATE LIMIT: Window expired for $identifier ($action_type) - resetting");
            $this->incrementAttempt($identifier, $action_type, $window_start);
            return true;
        }

        // Caso 4: il limite max_attempts è stato AUMENTATO nella configurazione
        // dopo che l'utente era stato bloccato → sblocca automaticamente
        // (evita che vecchi blocchi con limiti più bassi rimangano attivi)
        if ($record['is_blocked'] && $record['attempt_count'] < $config['max_attempts']) {
            $this->unblockIdentifier($identifier, $action_type);
            error_log("RATE LIMIT: Unblocked $identifier for $action_type (limit increased)");
            $this->securityLogger->log('rate_limit_unblocked', 'INFO', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'reason'      => 'limit_increased'
            ]);
            $record['is_blocked'] = 0;
        }

        // Caso 5: identifier ancora bloccato → controlla se il blocco è scaduto
        if ($record['is_blocked']) {
            // Durata blocco = window_minutes * 2 (penalità doppia)
            $block_expiry = strtotime($record['first_attempt'] . ' +' . ($config['window_minutes'] * 2) . ' minutes');

            if (time() < $block_expiry) {
                // Blocco ancora attivo → rifiuta e logga
                error_log("RATE LIMIT: $identifier still blocked for $action_type until " . date('Y-m-d H:i:s', $block_expiry));
                $this->securityLogger->log('rate_limit_still_blocked', 'WARNING', [
                    'identifier'   => $identifier,
                    'action_type'  => $action_type,
                    'block_expiry' => date('Y-m-d H:i:s', $block_expiry)
                ]);
                return false;
            }

            // Caso 6: blocco scaduto → resetta e riparti da zero
            $this->resetLimit($identifier, $action_type);
            $this->incrementAttempt($identifier, $action_type, $window_start);
            return true;
        }

        // Caso 7: contatore già al limite (o sopra) → blocca l'identifier
        // Questo gestisce il caso in cui il blocco non era stato ancora impostato
        // (race condition lenta) o il limite è stato raggiunto esattamente ora
        if ($record['attempt_count'] >= $config['max_attempts']) {
            $this->blockIdentifier($identifier, $action_type);
            error_log("RATE LIMIT: $identifier blocked for $action_type (exceeded {$config['max_attempts']} attempts in {$config['window_minutes']} minutes)");
            $this->securityLogger->log('rate_limit_blocked', 'WARNING', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'attempts'    => $record['attempt_count'],
                'max_allowed' => $config['max_attempts']
            ]);
            return false;
        }

        // Caso 8: sotto il limite → incrementa il contatore e permetti
        $this->incrementAttempt($identifier, $action_type, $window_start);
        return true;
    }

    /**
     * incrementAttempt() — Incrementa il contatore per un identifier in modo atomico.
     *
     * Usa INSERT ON DUPLICATE KEY UPDATE per garantire atomicità:
     * anche con richieste concorrenti, il valore viene incrementato correttamente
     * senza race condition (non serve un lock esplicito).
     *
     * La logica IF nella UPDATE:
     *  - Se last_attempt è fuori dalla finestra → resetta a 1 (nuova finestra)
     *  - Altrimenti → incrementa il contatore esistente
     *
     * @param string $identifier   Identificatore
     * @param string $action_type  Tipo azione
     * @param string $window_start Inizio finestra temporale (formato Y-m-d H:i:s)
     */
    private function incrementAttempt($identifier, $action_type, $window_start) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO rate_limits (identifier, action_type, attempt_count, first_attempt, last_attempt, is_blocked)
                VALUES (?, ?, 1, NOW(), NOW(), 0)
                ON DUPLICATE KEY UPDATE
                    attempt_count = IF(last_attempt < ?, 1, attempt_count + 1),
                    first_attempt = IF(last_attempt < ?, NOW(), first_attempt),
                    last_attempt  = NOW(),
                    is_blocked    = 0
            ");
            // I due $window_start sono per le due clausole IF nella UPDATE
            $stmt->execute([$identifier, $action_type, $window_start, $window_start]);

            error_log("RATE LIMIT: Incremented attempt for $identifier ($action_type)");

        } catch (PDOException $e) {
            error_log("RATE LIMIT ERROR: Failed to increment for $identifier - " . $e->getMessage());
            $this->securityLogger->log('rate_limit_increment_failed', 'CRITICAL', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'error'       => $e->getMessage()
            ]);
            return;
        }
    }

    /**
     * blockIdentifier() — Imposta is_blocked=1 per fermare ulteriori tentativi.
     *
     * Chiamato internamente quando attempt_count raggiunge max_attempts.
     * Il blocco persiste nel DB fino alla scadenza (window_minutes * 2)
     * o fino allo sblocco manuale da admin.
     *
     * @param string $identifier   Identificatore da bloccare
     * @param string $action_type  Tipo azione
     */
    private function blockIdentifier($identifier, $action_type) {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE rate_limits
                SET is_blocked = 1
                WHERE identifier = ? AND action_type = ?
            ");
            $stmt->execute([$identifier, $action_type]);
            error_log("RATE LIMIT: Blocked $identifier for $action_type");
        } catch (PDOException $e) {
            error_log("RATE LIMIT ERROR: Failed to block $identifier - " . $e->getMessage());
            $this->securityLogger->log('rate_limit_block_failed', 'CRITICAL', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'error'       => $e->getMessage()
            ]);
        }
    }

    /**
     * unblockIdentifier() — Sblocca un identifier e azzera il contatore.
     *
     * Usato internamente quando si rileva che il limite è stato aumentato
     * nel config dopo che l'utente era stato bloccato.
     *
     * @param string $identifier   Identificatore da sbloccare
     * @param string $action_type  Tipo azione
     */
    private function unblockIdentifier($identifier, $action_type) {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE rate_limits
                SET is_blocked = 0, attempt_count = 0
                WHERE identifier = ? AND action_type = ?
            ");
            $stmt->execute([$identifier, $action_type]);
            error_log("RATE LIMIT: Unblocked $identifier for $action_type");
        } catch (PDOException $e) {
            error_log("RATE LIMIT ERROR: Failed to unblock $identifier - " . $e->getMessage());
            $this->securityLogger->log('rate_limit_unblock_failed', 'CRITICAL', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'error'       => $e->getMessage()
            ]);
        }
    }

    /**
     * resetLimit() — Elimina completamente il record dal DB.
     *
     * Metodo pubblico perché login.php lo chiama dopo un login riuscito
     * (reset completo del contatore di fallimenti per quell'identifier).
     * Usato anche internamente dopo la scadenza della finestra temporale.
     *
     * @param string $identifier   Identificatore da resettare
     * @param string $action_type  Tipo azione
     */
    public function resetLimit($identifier, $action_type) {
        try {
            $stmt = $this->pdo->prepare("
                DELETE FROM rate_limits
                WHERE identifier = ? AND action_type = ?
            ");
            $stmt->execute([$identifier, $action_type]);
            error_log("RATE LIMIT: Reset limit for $identifier ($action_type)");
        } catch (PDOException $e) {
            error_log("RATE LIMIT ERROR: Failed to reset $identifier - " . $e->getMessage());
            $this->securityLogger->log('rate_limit_reset_failed', 'CRITICAL', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'error'       => $e->getMessage()
            ]);
        }
    }

    /**
     * isBlocked() — Controlla se un identifier è bloccato SENZA incrementare il contatore.
     *
     * Usato per azioni con esito binario (es. login, cambio password) dove il contatore
     * deve crescere SOLO in caso di fallimento. Questo metodo si occupa solo del controllo,
     * mentre recordFailedAttempt() si occupa dell'incremento.
     *
     * Gestisce automaticamente: finestre scadute, blocchi scaduti, limiti aumentati nel config.
     *
     * @param  string $identifier   Identificatore da controllare
     * @param  string $action_type  Tipo di azione
     * @return bool                 true = bloccato, false = libero
     */
    public function isBlocked($identifier, $action_type) {
        if (!isset($this->limits[$action_type])) {
            return false;
        }

        $config = $this->limits[$action_type];
        $window_start = date('Y-m-d H:i:s', strtotime("-{$config['window_minutes']} minutes"));

        $stmt = $this->pdo->prepare("
            SELECT attempt_count, is_blocked, first_attempt, last_attempt
            FROM rate_limits
            WHERE identifier = ? AND action_type = ?
        ");
        $stmt->execute([$identifier, $action_type]);
        $record = $stmt->fetch();

        if (!$record || $record['last_attempt'] < $window_start) {
            return false; // Nessun record o finestra scaduta: non bloccato
        }

        // Limite alzato nel config dopo il blocco → sblocca automaticamente
        if ($record['is_blocked'] && $record['attempt_count'] < $config['max_attempts']) {
            $this->unblockIdentifier($identifier, $action_type);
            return false;
        }

        if ($record['is_blocked']) {
            $block_expiry = strtotime($record['first_attempt'] . ' +' . ($config['window_minutes'] * 2) . ' minutes');
            if (time() < $block_expiry) {
                $this->securityLogger->log('rate_limit_still_blocked', 'WARNING', [
                    'identifier'   => $identifier,
                    'action_type'  => $action_type,
                    'block_expiry' => date('Y-m-d H:i:s', $block_expiry)
                ]);
                return true; // Ancora bloccato
            }
            // Blocco scaduto
            $this->resetLimit($identifier, $action_type);
            return false;
        }

        // Contatore al limite ma is_blocked non ancora impostato (race condition)
        if ($record['attempt_count'] >= $config['max_attempts']) {
            $this->blockIdentifier($identifier, $action_type);
            return true;
        }

        return false;
    }

    /**
     * recordFailedAttempt() — Registra un tentativo fallito e blocca se si raggiunge il limite.
     *
     * Chiamato SOLO quando l'azione ha esito negativo (password errata, ecc.).
     * I tentativi riusciti NON vengono conteggiati, evitando che un utente legittimo
     * si blocchi semplicemente usando il sistema.
     *
     * @param string $identifier   Identificatore (username, IP, user_id, ecc.)
     * @param string $action_type  Tipo di azione
     */
    public function recordFailedAttempt($identifier, $action_type) {
        if (!isset($this->limits[$action_type])) {
            return;
        }

        $config = $this->limits[$action_type];
        $window_start = date('Y-m-d H:i:s', strtotime("-{$config['window_minutes']} minutes"));

        $this->incrementAttempt($identifier, $action_type, $window_start);

        // Controlla se il contatore ha appena raggiunto il limite
        $stmt = $this->pdo->prepare("
            SELECT attempt_count FROM rate_limits
            WHERE identifier = ? AND action_type = ?
        ");
        $stmt->execute([$identifier, $action_type]);
        $record = $stmt->fetch();

        if ($record && $record['attempt_count'] >= $config['max_attempts']) {
            $this->blockIdentifier($identifier, $action_type);
            error_log("RATE LIMIT: $identifier blocked for $action_type after {$record['attempt_count']} failed attempts");
            $this->securityLogger->log('rate_limit_blocked', 'WARNING', [
                'identifier'  => $identifier,
                'action_type' => $action_type,
                'attempts'    => $record['attempt_count'],
                'max_allowed' => $config['max_attempts']
            ]);
        }
    }

    /**
     * getLimits() — Restituisce la configurazione dei limiti.
     *
     * Usato dal pannello admin e dalla pagina di login per mostrare
     * configurazioni e leggere max_attempts/window_minutes correnti.
     *
     * @return array<string, array{max_attempts: int, window_minutes: int}>
     */
    public function getLimits() {
        return $this->limits;
    }

    /**
     * forceUnblock() — Sblocco forzato manuale da parte dell'admin.
     *
     * Chiamato dal pannello di amministrazione quando un admin decide di
     * sbloccare manualmente un utente/IP. Elimina il record completamente
     * (come resetLimit) e logga l'azione admin per l'audit trail.
     *
     * @param string $identifier   Identificatore da sbloccare
     * @param string $action_type  Tipo azione
     */
    public function forceUnblock($identifier, $action_type) {
        $this->resetLimit($identifier, $action_type);
        $this->securityLogger->log('rate_limit_force_unblock', 'INFO', [
            'identifier'  => $identifier,
            'action_type' => $action_type,
            'forced_by'   => 'admin'  // indica che è stato uno sblocco manuale
        ]);
        error_log("RATE LIMIT: ADMIN forced unblock for $identifier ($action_type)");
    }

    /**
     * cleanup() — Pulizia periodica dei record vecchi (> 24 ore).
     *
     * Chiamato da SecurityLogger e dal pannello admin per mantenere
     * la tabella rate_limits snella. Rimuove record la cui last_attempt
     * è più vecchia di 24 ore (sono comunque scaduti dalla finestra).
     *
     * Nota: questa pulizia avviene anche automaticamente tramite
     * maintenance.php (con probabilità 1% ad ogni richiesta).
     */
    public function cleanup() {
        try {
            $stmt = $this->pdo->prepare("
                DELETE FROM rate_limits
                WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            $stmt->execute();
            $deleted = $stmt->rowCount();

            if ($deleted > 0) {
                error_log("RATE LIMIT: Cleaned up $deleted old records");
                $this->securityLogger->log('rate_limit_cleanup', 'INFO', [
                    'deleted_records' => $deleted
                ]);
            }
        } catch (PDOException $e) {
            error_log("RATE LIMIT ERROR: Cleanup failed - " . $e->getMessage());
            $this->securityLogger->log('rate_limit_cleanup_failed', 'CRITICAL', [
                'error' => $e->getMessage()
            ]);
        }
    }
}

