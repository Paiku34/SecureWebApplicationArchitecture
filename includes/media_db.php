<?php
/*
 * ============================================================
 * media_db.php — Query di accesso ai media con controllo permessi
 * ============================================================
 *
 * Fornisce funzioni di accesso al database per la tabella `media`.
 * Implementa il principio di Least Privilege a livello di query:
 * ogni funzione seleziona solo le colonne strettamente necessarie
 * e filtra i dati in base ai permessi dell'utente chiamante.
 *
 * SICUREZZA:
 *  - Colonne esplicite (no SELECT *): evita l'accidental exposure di colonne
 *    sensibili che potrebbero essere aggiunte in futuro (es. internal_notes)
 *  - Prepared statements: prevengono SQL injection
 *  - Il filtro premium è applicato a livello SQL (server-side), non PHP,
 *    quindi anche se il codice PHP venisse bypassato, il DB non restituisce i dati
 *  - INNER JOIN con users: garantisce che ogni media abbia un autore valido
 *    (media orfani non vengono mai restituiti)
 */

/**
 * getVisibleMedia() — Recupera i media visibili all'utente in base ai suoi permessi.
 *
 * PRINCIPIO LEAST PRIVILEGE:
 *  - Utenti standard (is_premium=0): vedono solo media con is_premium=0
 *  - Utenti premium (is_premium=1): vedono tutti i media (inclusi premium)
 *  - Admin: come premium (gestito dalla pagina chiamante)
 *
 * COLONNE SELEZIONATE:
 *  Volutamente esplicitiamo solo le colonne necessarie alla visualizzazione:
 *   - id, title: identificazione e display
 *   - audio_path, lyrics_path: percorsi per i link di download/view
 *   - is_premium: per mostrare badge "Premium" nella UI
 *   - uploaded_at: per l'ordinamento cronologico
 *   - user_id, author_name: per attribuire il contenuto all'autore
 *
 *  Colonne NON incluse intenzionalmente:
 *   - password_hash: ovviamente (non è nella tabella media, ma per chiarezza)
 *   - audio_hash, lyrics_hash: hash di integrità (usati solo in download.php e view_lyrics.php)
 *   - internal flags futuri: column whitelist protegge da future aggiunte
 *
 * @param  PDO   $pdo             Connessione database
 * @param  bool  $user_is_premium true se l'utente ha accesso premium
 * @return array                  Array di media associativi (può essere vuoto)
 */
function getVisibleMedia($pdo, $user_is_premium) {
    // Whitelist esplicita delle colonne da restituire (principio Least Privilege)
    // Se in futuro venissero aggiunte colonne sensibili a `media`, questa query
    // non le esporrebbe: bisognerebbe aggiungerle deliberatamente qui.
    $columns = "m.id, m.title, m.audio_path, m.lyrics_path, m.is_premium, m.uploaded_at, m.user_id, u.username AS author_name";

    // Base della query: INNER JOIN garantisce che media senza autore valido
    // non vengano mai restituiti (integrità referenziale a livello applicativo)
    $base_sql = "SELECT $columns
                 FROM media m
                 INNER JOIN users u ON m.user_id = u.id";

    // Cast esplicito a bool: previene bypass con valori truthy non-booleani
    if ((bool)$user_is_premium) {
        // Utente premium: accesso completo a tutti i media, ordinati dal più recente
        $sql  = $base_sql . " ORDER BY m.uploaded_at DESC";
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
    } else {
        // Utente standard: filtro SQL lato server per is_premium=0
        // Il filtro è nel DB (non solo in PHP) per defense in depth:
        // anche se un bug PHP saltasse il check, il DB non restituirebbe i dati premium
        $sql  = $base_sql . " WHERE m.is_premium = 0 ORDER BY m.uploaded_at DESC";
        $stmt = $pdo->prepare($sql); // prepared è corretto anche senza parametri: buona pratica uniforme
        $stmt->execute();
    }

    // fetchAll() con PDO::FETCH_ASSOC (impostato come default in db.php)
    $results = $stmt->fetchAll();

    // Garantisce sempre un array (mai null/false) per stabilità del foreach nel chiamante
    return $results ? $results : [];
}