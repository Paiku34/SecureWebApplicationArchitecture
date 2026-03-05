<?php
/*
 * ============================================================
 * db.php — Connessione sicura al database MySQL/MariaDB via PDO
 * ============================================================
 *
 * Questo file stabilisce l'unica connessione PDO dell'applicazione.
 * Viene incluso prima di ogni operazione sul database.
 *
 * SICUREZZA:
 *  - Le credenziali vengono caricate SOLO da variabili d'ambiente Docker
 *    (mai hardcoded nel codice, mai in file .env tracciati da git)
 *  - PDO::ATTR_EMULATE_PREPARES = false: usa prepared statements nativi
 *    del driver MySQL → prevenzione SQL injection a livello driver
 *  - PDO::ATTR_PERSISTENT = false: connessioni non persistenti per evitare
 *    saturazione del pool di connessioni MySQL
 *  - ERRMODE_EXCEPTION: gli errori SQL lanciano eccezioni → possono essere
 *    catturate e gestite senza esporre dettagli all'utente finale
 *  - sql_mode STRICT_ALL_TABLES: il DB rifiuta dati troncati o invalidi
 *    (es. stringa troppo lunga per VARCHAR) invece di silenziarli
 *  - In caso di errore di connessione, il messaggio all'utente è generico
 *    e NON contiene dettagli tecnici (host, DB name, credenziali)
 *
 * CONFIGURAZIONE TIMEZONE:
 *  Sincronizziamo PHP e MySQL su Europe/Rome (+01:00 / +02:00 DST).
 *  Questo garantisce coerenza tra i timestamp di PHP (time(), date())
 *  e quelli salvati/letti dal DB (NOW(), TIMESTAMP columns).
 *
 * CHARSET:
 *  utf8mb4 supporta l'intero Unicode (inclusi emoji) a differenza di
 *  utf8 MySQL che è solo 3-byte. Necessario per nomi utente moderni.
 */

// Imposta il fuso orario PHP (deve coincidere con quello del DB per coerenza)
date_default_timezone_set('Europe/Rome');

// ─── Lettura credenziali da variabili d'ambiente ──────────────────────────────
// Le env vars vengono iniettate da docker-compose.yml e mai esposte nel codice.
// Questo rispetta il principio 12-Factor App (config separata dal codice).
$host    = 'db';                          // hostname del container MySQL in Docker
$db      = getenv('MYSQL_DATABASE');      // nome del database
$user    = getenv('MYSQL_USER');          // utente MySQL (NON root in produzione)
$pass    = getenv('MYSQL_PASSWORD');      // password MySQL
$charset = 'utf8mb4';                     // charset completo Unicode 4-byte

// Verifica che tutte le credenziali siano disponibili prima di procedere.
// Se mancano, l'applicazione si ferma con un messaggio generico
// (non rivela quale variabile sia mancante per non aiutare l'attaccante).
if (!$db || !$user || !$pass) {
    // Log interno dettagliato (visibile solo agli admin via docker logs)
    error_log("CRITICAL: Database credentials missing in environment variables.");
    // Messaggio generico all'utente: no stack trace, no nomi variabili
    exit("Errore di configurazione interna.");
}

// ─── Data Source Name (DSN) ──────────────────────────────────────────────────
// charset nel DSN garantisce che la negoziazione avvenga prima di qualsiasi query,
// prevenendo possibili charset confusion attacks su MySQL < 5.7
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

// ─── Opzioni PDO ─────────────────────────────────────────────────────────────
$options = [
    // Lancia PDOException per ogni errore SQL → gestione esplicita nel codice
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,

    // Fetch come array associativo per default (leggibile e sicuro)
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,

    // CRITICO per la sicurezza: disabilita l'emulazione dei prepared statements.
    // Con false, il driver invia la query e i parametri separatamente al server
    // MySQL → il server non può mai confondere i parametri con SQL.
    // Con true (default), PDO simula i prepared statements in PHP e poi
    // concatena la stringa finale → vulnerabile a injection in edge case.
    PDO::ATTR_EMULATE_PREPARES   => false,

    // No connessioni persistenti: evita che un utente erediti lo stato
    // (transazioni aperte, variabili di sessione) di una connessione precedente
    PDO::ATTR_PERSISTENT         => false,

    // Comando eseguito ad ogni nuova connessione:
    //  SET NAMES utf8mb4     → garantisce encoding uniforme per tutte le query
    //  time_zone = '+01:00'  → allinea timezone DB a quella PHP (Europe/Rome)
    //  sql_mode STRICT_ALL_TABLES → rifiuta dati invalidi/troncati (fail-fast)
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, time_zone = '+01:00', sql_mode = 'STRICT_ALL_TABLES'"
];

// ─── Tentativo di connessione ─────────────────────────────────────────────────
try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // IMPORTANTE: non loggare $e->getMessage() nella risposta HTTP perché
    // può contenere credenziali, hostname e dettagli dell'infrastruttura.
    // Logghiamo solo l'IP per il debug, senza dati sensibili.
    error_log("Database connection failed from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

    // HTTP 503 Service Unavailable: comunica che il servizio è temporaneamente down
    http_response_code(503);
    // Messaggio utente generico, senza dettagli tecnici
    exit("Il servizio è momentaneamente non raggiungibile. Riprova tra pochi minuti.");
}
