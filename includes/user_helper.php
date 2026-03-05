<?php
/*
 * ============================================================
 * user_helper.php — Utility per il recupero ottimizzato dei dati utente
 * ============================================================
 *
 * Fornisce funzioni per recuperare i dati utente dal database con un sistema
 * di cache in sessione (TTL 5 minuti) per ridurre il carico sul DB.
 *
 * MOTIVAZIONE DELLA CACHE IN SESSIONE:
 *  Molte pagine (dashboard, media, download, upload) hanno bisogno dei dati
 *  dell'utente (username, is_premium, is_admin) per ogni richiesta.
 *  Senza cache, questo genera N query al DB per ogni utente per ogni pagina.
 *  La cache in sessione riutilizza i dati se sono freschi (< 5 minuti),
 *  riducendo il carico del DB nelle sessioni attive.
 *
 * SICUREZZA:
 *  - TTL di 5 minuti: bilanciamento tra performance e freschezza dei dati.
 *    Un ban admin impiega al massimo 5 minuti per essere riflesso qui,
 *    ma validate_session() controlla is_banned in real-time (senza cache)
 *    quindi il ban è effettivo immediatamente indipendentemente da questa cache.
 *  - force_refresh = true: usato per forzare il reload dopo operazioni che
 *    modificano i dati utente (es. cambio password, upgrade premium)
 *  - Colonne esplicite nella SELECT: no password_hash, no dati interni
 *
 * INVALIDAZIONE CACHE:
 *  Chiamare invalidate_user_cache() dopo qualsiasi operazione che modifica
 *  i dati utente (profile update, admin toggle premium/ban) per garantire
 *  che la prossima richiesta legga i dati aggiornati dal DB.
 */

declare(strict_types=1);

/**
 * get_user_data() — Recupera i dati utente con cache in sessione.
 *
 * LOGICA CACHE:
 *  1. Se force_refresh=false E cache presente E cache non scaduta → ritorna cache
 *  2. Altrimenti → query DB, aggiorna cache, ritorna dati freschi
 *
 * COLONNE SELEZIONATE:
 *  Solo le colonne necessarie per la UI e i controlli di accesso.
 *  password_hash è volutamente esclusa: non serve mai nella cache utente.
 *
 * @param  PDO   $pdo            Connessione database
 * @param  int   $user_id        ID utente da recuperare
 * @param  bool  $force_refresh  true = bypassa la cache e interroga sempre il DB
 * @return array|null            Dati utente associativi, o null se non trovato
 */
function get_user_data(PDO $pdo, int $user_id, bool $force_refresh = false): ?array {
    // Chiavi di sessione univoche per utente (sicuro: user_id è int, no collisioni)
    $cache_key      = 'user_data_' . $user_id;
    $cache_time_key = 'user_data_time_' . $user_id;
    $cache_ttl      = 300; // 5 minuti in secondi

    // Verifica se la cache è ancora valida:
    //  1. force_refresh=false: il chiamante non ha chiesto un refresh esplicito
    //  2. Cache presente in sessione: i dati esistono
    //  3. Cache non scaduta: i dati sono stati letti meno di 5 minuti fa
    if (!$force_refresh &&
        isset($_SESSION[$cache_key]) &&
        isset($_SESSION[$cache_time_key]) &&
        (time() - $_SESSION[$cache_time_key]) < $cache_ttl) {
        // HIT di cache: nessuna query al DB
        return $_SESSION[$cache_key];
    }

    // MISS di cache: interroga il database
    // Nota: NON seleziona password_hash (principio Least Privilege)
    // Nota: is_banned è incluso per verifica di consistenza (il check real-time
    //       è in validate_session, questa è una lettura informativa)
    $stmt = $pdo->prepare("
        SELECT id, username, email, is_premium, is_admin, is_banned,
               total_uploads, total_downloads_received,
               created_at, last_login
        FROM users
        WHERE id = ?
    ");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Aggiorna la cache solo se l'utente esiste nel DB
    // (non cachare null: se l'utente non esiste, vogliamo saperlo ad ogni richiesta)
    if ($user) {
        $_SESSION[$cache_key]      = $user;     // dati utente
        $_SESSION[$cache_time_key] = time();    // timestamp del fetch
    }

    // Ritorna i dati o null se l'utente non esiste (account eliminato?)
    return $user ?: null;
}

/**
 * invalidate_user_cache() — Invalida la cache per un utente specifico.
 *
 * Da chiamare SEMPRE dopo operazioni che modificano i dati utente nel DB:
 *  - Cambio username/email (profile.php)
 *  - Toggle premium/ban da admin (admin.php)
 *  - Cambio password (change_password.php)
 *  - Qualsiasi UPDATE sulla tabella users per questo user_id
 *
 * Senza invalidazione, le modifiche impiegano fino a 5 minuti a essere visibili.
 * Per le operazioni di sicurezza critiche (ban), validate_session() controlla
 * il DB direttamente quindi il ban è comunque immediato.
 *
 * @param int $user_id  ID utente di cui invalidare la cache
 */
function invalidate_user_cache(int $user_id): void {
    // Rimuove entrambe le chiavi: dati e timestamp
    // Alla prossima chiamata a get_user_data(), verrà fatto un fresh fetch dal DB
    unset($_SESSION['user_data_' . $user_id]);
    unset($_SESSION['user_data_time_' . $user_id]);
}
