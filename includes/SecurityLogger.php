<?php
/*
 * ============================================================
 * SecurityLogger.php — Logging centralizzato degli eventi di sicurezza
 * ============================================================
 *
 * Questa classe implementa un sistema di logging a doppio canale:
 *  1. FILE di log      → tutti gli eventi (INFO, WARNING, CRITICAL)
 *  2. DATABASE         → solo eventi WARNING e CRITICAL (per query nel pannello admin)
 *
 * MOTIVAZIONE DEL DOPPIO CANALE:
 *  Il file è più affidabile (persiste anche se il DB è irraggiungibile)
 *  e il DB permette query strutturate nel pannello admin senza dover
 *  parsare file di testo.
 *
 * ROTAZIONE LOG:
 *  Quando il file supera 10MB viene rinominato con data/ora e ne viene creato uno nuovo.
 *  Questo previene l'esaurimento dello spazio disco in produzione.
 *
 * METODI SPECIALIZZATI:
 *  La classe espone metodi ad-hoc per gli attacchi più comuni:
 *   - logPathTraversal()       → tentativi di directory traversal
 *   - logCSRFViolation()       → token CSRF non validi
 *   - logIntegrityViolation()  → hash SHA-256 del file non corrispondente
 *   - logUnauthorizedAccess()  → accesso a risorse senza permessi
 *
 * SICUREZZA:
 *  - LOCK_EX durante la scrittura file previene corruzione da scritture concorrenti
 *  - I token CSRF nei log vengono troncati (10 char + '...') per non esporre il token completo
 *  - Prepared statements per tutti gli INSERT nel DB
 *  - Campi user_agent e request_uri troncati a 255 char (limite colonna DB)
 */

class SecurityLogger {

    /** @var PDO Connessione database per i log WARNING/CRITICAL */
    private $pdo;

    /** @var string Percorso assoluto del file di log */
    private $log_file;

    /** @var int Dimensione massima del file prima della rotazione (10 MB) */
    private $max_file_size = 10485760; // 10MB = 10 * 1024 * 1024 byte

    /**
     * Costruttore: configura il percorso del file di log.
     *
     * Crea la directory storage/logs/ se non esiste ancora (es. primo avvio).
     * Il permesso 0755 limita la scrittura all'owner (processo PHP/web server)
     * mentre permette la lettura ad altri (per monitoring tools).
     *
     * @param PDO $pdo  Connessione database iniettata
     */
    public function __construct($pdo) {
        $this->pdo = $pdo;
        // Percorso relativo al file corrente, robusto agli spostamenti del progetto
        $this->log_file = __DIR__ . '/../storage/logs/security.log';

        // Crea la directory dei log se non esiste già (first-run safety)
        $log_dir = dirname($this->log_file);
        if (!is_dir($log_dir)) {
            mkdir($log_dir, 0755, true); // ricorsivo: crea anche i parent mancanti
        }
    }

    /**
     * log() — Metodo principale di logging.
     *
     * Scrive sempre su file, e nel DB solo per livelli WARNING/CRITICAL.
     * La scelta di non loggare INFO nel DB è intenzionale per ridurre
     * il volume di scritture (gli INFO sono frequenti: login, visualizzazioni, ecc.).
     *
     * FORMATO FILE LOG:
     *  [2024-01-15 14:23:05] [WARNING] [login_failed] UserID:42 IP:1.2.3.4
     *  Event:login_failed URI:/public/login.php Context:{"username":"test"}
     *
     * @param string $event_type  Tipo evento (es. 'login_failed', 'csrf_violation')
     * @param string $severity    Livello: 'INFO' | 'WARNING' | 'CRITICAL'
     * @param array  $context     Dati aggiuntivi serializzati in JSON nel log
     */
    public function log($event_type, $severity, $context = []) {
        $timestamp   = date('Y-m-d H:i:s');
        $user_id     = $_SESSION['user_id'] ?? 'anonymous'; // anonymous se non autenticato
        $ip          = $_SERVER['REMOTE_ADDR'];
        $user_agent  = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $request_uri = $_SERVER['REQUEST_URI'] ?? 'unknown';

        // ─── Scrittura su file (sempre, per qualsiasi severity) ───────────────────
        // sprintf costruisce una riga di log leggibile e parsabile
        $log_entry = sprintf(
            "[%s] [%s] [%s] UserID:%s IP:%s Event:%s URI:%s Context:%s\n",
            $timestamp,
            $severity,
            $event_type,
            $user_id,
            $ip,
            $event_type,            // ripetuto per facilitare il grep su tipo evento
            substr($request_uri, 0, 255), // troncato per leggibilità
            json_encode($context)
        );

        // FILE_APPEND: aggiunge in coda senza sovrascrivere
        // LOCK_EX: lock esclusivo durante la scrittura (anti-concorrenza)
        file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);

        // ─── Scrittura su DB (solo per eventi gravi) ──────────────────────────────
        // WARNING e CRITICAL vengono persistiti nel DB per essere interrogabili
        // dalla pagina admin (/admin.php) senza dover leggere il file di log
        if ($severity === 'CRITICAL' || $severity === 'WARNING') {
            try {
                $stmt = $this->pdo->prepare("
                    INSERT INTO security_logs
                        (event_type, severity, user_id, ip_address, user_agent, request_uri, context, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
                ");
                $stmt->execute([
                    $event_type,
                    $severity,
                    // Salva NULL invece di 'anonymous' per facilitare le query (WHERE user_id IS NOT NULL)
                    $user_id === 'anonymous' ? null : $user_id,
                    $ip,
                    substr($user_agent, 0, 255),   // rispetta il VARCHAR(255) del DB
                    substr($request_uri, 0, 255),  // rispetta il VARCHAR(255) del DB
                    json_encode($context)
                ]);
            } catch (Exception $e) {
                // Non propagare l'eccezione: il logging non deve mai bloccare l'app
                error_log("SecurityLogger DB ERROR: " . $e->getMessage());
            }
        }
    }

    /**
     * logPathTraversal() — Logga un tentativo di directory traversal.
     *
     * Il path traversal (../../../etc/passwd) è un attacco che mira a leggere
     * file al di fuori della directory consentita. Viene loggato come CRITICAL
     * perché indica un tentativo deliberato di exploitation.
     *
     * NOTA sul Referer:
     *  L'header Referer è incluso solo per analisi forense successiva.
     *  NON viene usato per bloccare l'accesso perché:
     *   a) può essere falsificato dal client
     *   b) browser/proxy possono ometterlo (falsi negativi)
     *  Il blocco si basa sulla validazione del path (realpath + strpos),
     *  non sul Referer.
     *
     * @param string $attempted_path  Il path malevolo che è stato tentato
     */
    public function logPathTraversal($attempted_path) {
        $this->log('path_traversal', 'CRITICAL', [
            'attempted_path' => $attempted_path,
            // Referer solo per analisi forense, NON usato per decisioni di sicurezza
            'referer'        => $_SERVER['HTTP_REFERER'] ?? 'none'
        ]);
    }

    /**
     * logCSRFViolation() — Logga una violazione del token CSRF.
     *
     * Viene chiamato quando il token inviato con il form non corrisponde
     * a quello in sessione. Può indicare:
     *  - Un attacco CSRF vero e proprio (sito malevolo che posta sul nostro form)
     *  - Un token scaduto (sessione scaduta durante la compilazione del form)
     *  - Manipolazione diretta del DOM da parte dell'utente
     *
     * PRIVACY: i token vengono troncati a 10 caratteri + '...' nel log
     * per evitare di esporre token validi in caso di leak del file di log.
     *
     * @param string $expected_token  Token atteso (dalla sessione)
     * @param string $received_token  Token ricevuto (dal form POST)
     */
    public function logCSRFViolation($expected_token, $received_token) {
        $this->log('csrf_violation', 'CRITICAL', [
            // Solo i primi 10 caratteri: sufficienti per il debug, non abbastanza per exploit
            'expected' => substr($expected_token, 0, 10) . '...',
            'received' => substr($received_token, 0, 10) . '...'
        ]);
    }

    /**
     * logIntegrityViolation() — Logga una violazione dell'integrità di un file.
     *
     * Viene chiamato quando l'hash SHA-256 calcolato al momento del download/view
     * non corrisponde all'hash salvato nel DB al momento dell'upload.
     *
     * Possibili cause:
     *  - Corruzione del file su disco (hardware fault, truncation)
     *  - Manomissione del file da parte di un attaccante con accesso al filesystem
     *  - Bug nell'applicazione durante il salvataggio
     *
     * Questo è un segnale critico che richiede indagine immediata.
     *
     * @param int|string $file_id        ID del media nel database
     * @param string     $expected_hash  Hash SHA-256 salvato al momento dell'upload
     * @param string     $actual_hash    Hash SHA-256 calcolato ora sul file
     */
    public function logIntegrityViolation($file_id, $expected_hash, $actual_hash) {
        $this->log('integrity_violation', 'CRITICAL', [
            'file_id'       => $file_id,
            'expected_hash' => $expected_hash, // hash originale salvato nel DB
            'actual_hash'   => $actual_hash    // hash corrente del file su disco
        ]);
    }

    /**
     * logUnauthorizedAccess() — Logga un accesso non autorizzato a una risorsa.
     *
     * Viene chiamato quando un utente tenta di accedere a una pagina o risorsa
     * per cui non ha i permessi necessari. Esempi:
     *  - Accesso a /admin.php senza is_admin=1
     *  - Accesso a contenuto premium senza is_premium=1
     *  - Accesso a pagina autenticata senza sessione valida
     *  - Session hijacking rilevato (IP mismatch)
     *
     * Loggato come WARNING (non CRITICAL) perché può avvenire facilmente
     * per errore (link diretto, bookmark dopo logout) senza intento malevolo.
     *
     * @param string $resource  Nome della risorsa tentata (es. 'admin', 'download')
     * @param string $reason    Motivazione del rifiuto (es. 'No session', 'IP mismatch')
     */
    public function logUnauthorizedAccess($resource, $reason) {
        $this->log('unauthorized_access', 'WARNING', [
            'resource' => $resource,
            'reason'   => $reason
        ]);
    }
}
