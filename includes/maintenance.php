<?php
/*
 * ============================================================
 * maintenance.php — Task di pulizia automatica del database
 * ============================================================
 *
 * Questo file implementa un sistema di manutenzione "probabilistica" che
 * elimina la necessità di cron job dedicati in ambienti limitati (es. Docker dev).
 *
 * STRATEGIA "1% RANDOM":
 *  Invece di usare un cron job che esegue cleanup ogni N ore, questo modulo
 *  viene invocato da validate_session() con una probabilità dell'1% (1 su 100
 *  richieste). In media, su 100 richieste/min otteniamo ~1 cleanup/min.
 *  Questo approccio:
 *   + Non richiede cron, supervisord o timer systemd
 *   + Non aggiunge overhead percettibile all'utente (99% delle richieste lo saltano)
 *   + Funziona automaticamente anche in ambienti containerizzati
 *   - Leggera imprecisione temporale (cleanup ogni ~100 richieste, non ogni X ore esatte)
 *
 * COSA VIENE PULITO:
 *  1. rate_limits vecchi (> 24h da last_attempt)
 *     → Record inutili: se l'ultimo tentativo è > 24h fa, la finestra è sicuramente scaduta
 *  2. password_resets scaduti o già usati (> 7 giorni)
 *     → Token scaduti o usati non devono rimanere nel DB: ogni token è one-shot
 *  3. File di log > 10MB
 *     → Rotazione: rinomina il file corrente con timestamp e ne crea uno nuovo vuoto
 *
 * SICUREZZA:
 *  - Failure silenzioso in maybe_run_maintenance(): un errore di cleanup non deve
 *    mai interrompere la richiesta utente (availability > perfect housekeeping)
 *  - force_maintenance() invece è esplicito (usato dall'admin) e ritorna i risultati
 */

declare(strict_types=1);

/**
 * maybe_run_maintenance() — Esegue il cleanup con probabilità 1% ad ogni chiamata.
 *
 * Viene chiamata automaticamente da validate_session() in authentication.php.
 * Non richiede chiamata esplicita da parte dello sviluppatore.
 *
 * PROBABILITÀ:
 *  random_int(1, 100) === 1  →  probabilità esattamente 1%
 *  Usiamo random_int (CSPRNG) invece di rand() per evitare pattern prevedibili
 *  (anche se per questa funzione non è critico, è buona pratica).
 *
 * @param PDO $pdo  Connessione database
 */
function maybe_run_maintenance(PDO $pdo): void {
    // Esci immediatamente nel 99% dei casi (no overhead)
    if (random_int(1, 100) !== 1) {
        return;
    }

    try {
        // ─── Pulizia 1: record rate_limits scaduti ────────────────────────────────
        // I record con last_attempt > 24h sono certamente fuori da qualsiasi finestra
        // temporale (la finestra più lunga è 24h per login/password_change).
        // Tenerli sarebbe solo spreco di spazio e indexing overhead.
        $stmt = $pdo->prepare("
            DELETE FROM rate_limits
            WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stmt->execute();
        $deleted_rate = $stmt->rowCount();

        // ─── Pulizia 2: token di reset password obsoleti ─────────────────────────
        // Un token di reset viene rimosso se ENTRAMBE le condizioni sono vere:
        //  a) è scaduto (expires_at < NOW()) O è già stato usato (used_at IS NOT NULL)
        //  b) è stato creato > 7 giorni fa (grace period per analisi forense)
        // Il grace period di 7 giorni permette di investigare possibili abusi recenti.
        $stmt = $pdo->prepare("
            DELETE FROM password_resets
            WHERE (expires_at < NOW() OR used_at IS NOT NULL)
            AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        $stmt->execute();
        $deleted_resets = $stmt->rowCount();

        // ─── Pulizia 3: rotazione del file di log ─────────────────────────────────
        // Se il file security.log supera 10MB, viene rinominato con la data
        // e il processo di logging creerà automaticamente un nuovo file vuoto.
        // Questo previene l'esaurimento del disco in produzione.
        $log_file = __DIR__ . '/../storage/logs/security.log';
        if (file_exists($log_file) && filesize($log_file) > 10485760) {
            // Formato: security.log.old.2024-01-15 (un file per giorno)
            rename($log_file, $log_file . '.old.' . date('Y-m-d'));
        }

        // Log interno solo se c'è stata attività effettiva (evita spam nel PHP error_log)
        if ($deleted_rate > 0 || $deleted_resets > 0) {
            error_log(sprintf(
                "[MAINTENANCE] Cleanup: %d rate_limits, %d password_resets rimossi",
                $deleted_rate,
                $deleted_resets
            ));
        }

    } catch (Exception $e) {
        // FALLIMENTO SILENZIOSO: un errore di manutenzione NON deve mai
        // bloccare la richiesta dell'utente (principio di availability).
        // L'errore viene comunque loggato nel PHP error_log per il debug.
        error_log("[MAINTENANCE ERROR] " . $e->getMessage());
    }
}

/**
 * force_maintenance() — Esegue il cleanup forzato con reporting dei risultati.
 *
 * Versione esplicita per il pannello admin: esegue sempre il cleanup (no 1%)
 * e restituisce un report con quanti record sono stati rimossi.
 * Chiamato da admin.php quando l'admin clicca "Esegui manutenzione".
 *
 * @param  PDO   $pdo  Connessione database
 * @return array       Report: ['rate_limits' => int, 'password_resets' => int, 'log_rotated' => bool]
 */
function force_maintenance(PDO $pdo): array {
    // Inizializza il report con valori di default
    $results = [
        'rate_limits'     => 0,     // numero record rate_limits rimossi
        'password_resets' => 0,     // numero token reset rimossi
        'log_rotated'     => false  // true se il file di log è stato ruotato
    ];

    try {
        // Pulizia rate_limits (stessa logica di maybe_run_maintenance)
        $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        $stmt->execute();
        $results['rate_limits'] = $stmt->rowCount();

        // Pulizia password_resets (stessa logica di maybe_run_maintenance)
        $stmt = $pdo->prepare("DELETE FROM password_resets WHERE (expires_at < NOW() OR used_at IS NOT NULL) AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stmt->execute();
        $results['password_resets'] = $stmt->rowCount();

        // Rotazione log con timestamp più preciso (ore/min/sec) per identificare
        // più rotazioni nello stesso giorno (es. durante test di carico)
        $log_file = __DIR__ . '/../storage/logs/security.log';
        if (file_exists($log_file) && filesize($log_file) > 10485760) {
            rename($log_file, $log_file . '.old.' . date('Y-m-d-His'));
            $results['log_rotated'] = true;
        }

    } catch (Exception $e) {
        // Qui logghiamo l'errore ma non lo rilanciamo:
        // il chiamante riceverà comunque un report parziale
        error_log("[FORCE MAINTENANCE ERROR] " . $e->getMessage());
    }

    return $results;
}
