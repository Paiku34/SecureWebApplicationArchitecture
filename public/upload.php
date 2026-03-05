<?php

/*
 * ============================================================
 * upload.php — Interfaccia form per l'upload di file audio e testi
 * ============================================================
 *
 * Pagina di presentazione del form upload. Tutta la validazione e il
 * salvataggio avviene in upload_control.php (controller separato).
 * Questo file gestisce solo il rendering sicuro del form.
 *
 *  1. VERIFICA SESSIONE + IP BINDING:
 *     validate_session() + controllo IP. Session hijacking bloccato.
 *
 *  2. CSRF TOKEN NEL FORM:
 *     generate_csrf_token() genera (se non esiste) un token in sessione.
 *     Il token viene inserito come hidden input nel form.
 *     upload_control.php lo verifica con hash_equals() prima di processare.
 *
 *  3. NESSUN OUTPUT DATI SENSIBILI:
 *     La pagina non espone path del server, configurazioni, o dati di altri utenti.
 *
 *  4. VALIDAZIONE LATO CLIENT (NON SUFFICIENTE DA SOLA):
 *     JavaScript pre-verifica tipo file, dimensione e lunghezza titolo per UX.
 *     upload_control.php ri-esegue tutti i controlli lato server indipendentemente.
 *
 *  5. SECURITY HEADERS:
 *     set_security_headers() imposta CSP, X-Frame-Options, HSTS, ecc.
 *     CSP limita le origini di script/style per ridurre la superficie XSS.
 */

require_once '../includes/authentication.php';
require_once '../includes/db.php';
require_once '../includes/SecurityLogger.php';
require_once '../includes/user_helper.php';

// Inizializza SecurityLogger
$securityLogger = new SecurityLogger($pdo);

if (!isset($_SESSION['user_id'])) {
    $securityLogger->logUnauthorizedAccess('upload', 'No session');
    $_SESSION['flash_message'] = 'Sessione scaduta. Effettua il login per continuare.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

// Controllo IP Binding (anti session hijacking)
if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    $securityLogger->logUnauthorizedAccess('upload', 'IP mismatch');
    $_SESSION['flash_message'] = 'Sessione non valida. Indirizzo IP non corrispondente.';
    $_SESSION['flash_type'] = 'error';
    header('Location: login.php?error=session_invalid');
    exit();
}

if (!validate_session($pdo)) {
    header('Location: login.php?error=session_invalid');
    exit();
}

// Generazione Token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Log accesso pagina upload (solo primo accesso nella sessione)
if (!isset($_SESSION['upload_page_logged'])) {
    $securityLogger->log('upload_page_access', 'INFO', [
        'user_id' => $_SESSION['user_id']
    ]);
    $_SESSION['upload_page_logged'] = true;
}

// Security Headers centralizzati
set_security_headers();

// Recupero dati utente per la navbar (con caching)
$user = get_user_data($pdo, $_SESSION['user_id'], false);

// Sanitizzazione output (già presente e corretta)
$username_safe = htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8');

// AGGIUNTO: Sanitizzazione parametro GET success (se presente)
$success_param = filter_input(INPUT_GET, 'success', FILTER_VALIDATE_INT);
?>

<!DOCTYPE html>
<html class="dark" lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nuovo Upload - Music Platform</title>
    
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body class="page-wrapper">
    
    <!-- Header -->
    <header class="header">
        <a href="dashboard.php" class="header-brand">
            🎵 MusicAdmin
        </a>
        <div class="header-user">
            <a href="dashboard.php" class="btn btn-secondary btn-sm">← Dashboard</a>
            <div class="user-avatar">
                <?php echo strtoupper(substr($username_safe, 0, 1)); ?>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <div class="main-content">
        <div class="container-small">
            
            <!-- Page Header -->
            <div class="card-header">
                <h1 class="card-title">Nuovo Upload</h1>
                <p class="card-subtitle">Aggiungi un nuovo brano al tuo catalogo musicale</p>
            </div>

            <!-- Success Message -->
            <?php if ($success_param === 1): ?>
            <div class="message message-success" id="success-alert">
                <strong>✓ Upload completato!</strong>
                <p class="mt-5">Il tuo brano è stato caricato con successo.</p>
            </div>
            <?php endif; ?>

            <!-- Upload Form -->
            <form class="card" action="upload_control.php" method="POST" enctype="multipart/form-data" id="upload-form">
                
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                <!-- Title -->
                <div class="form-group">
                    <label class="form-label" for="track-title">Titolo del brano</label>
                    <input 
                        class="form-input" 
                        id="track-title" 
                        name="title"
                        placeholder="Es. Midnight Summer Dream" 
                        type="text"
                        required
                        maxlength="100"
                    />
                </div>

                <!-- Files Grid -->
                <div class="grid grid-2">
                    
                    <!-- Audio File -->
                    <div class="form-group">
                        <label class="form-label">File Audio</label>
                        <div class="upload-zone">
                            <div class="upload-zone-icon">🎵</div>
                            <p class="my-10"><strong>Clicca o trascina qui</strong></p>
                            <p class="upload-zone-text">MP3 (max 10MB)</p>
                            <p class="upload-zone-text" id="audio-file-name"></p>
                            <input 
                                class="upload-file-input"
                                id="dropzone-file-audio"
                                name="audio_file"
                                type="file"
                                accept=".mp3,audio/mpeg"
                                required
                            />
                        </div>
                    </div>

                    <!-- Lyrics File -->
                    <div class="form-group">
                        <label class="form-label">Testo / Lyrics</label>
                        <div class="upload-zone">
                            <div class="upload-zone-icon">📄</div>
                            <p class="my-10"><strong>Clicca o trascina qui</strong></p>
                            <p class="upload-zone-text">TXT (max 1MB)</p>
                            <p class="upload-zone-text" id="lyrics-file-name"></p>
                            <input 
                                class="upload-file-input"
                                id="dropzone-file-lyrics"
                                name="lyrics_file"
                                type="file"
                                accept=".txt,text/plain"
                                required
                            />
                        </div>
                    </div>

                </div>

                <!-- Premium Checkbox -->
                <div class="form-group premium-box">
                    <label class="premium-label">
                        <input 
                            type="checkbox"
                            name="is_premium"
                            value="1"
                            id="premium-content"
                            class="premium-checkbox"
                        />
                        <div>
                            <strong class="text-primary">Contenuto Premium ⭐</strong>
                            <p class="text-muted mt-5">
                                Seleziona questa opzione se il brano deve essere accessibile solo agli utenti con abbonamento attivo.
                            </p>
                        </div>
                    </label>
                </div>

                <!-- Buttons -->
                <div class="btn-row">
                    <button type="submit" class="btn btn-primary" id="submit-btn">
                        📤 Carica File
                    </button>
                    <button type="button" class="btn btn-secondary" data-action="cancel-upload">
                        Annulla
                    </button>
                </div>

            </form>

        </div>
    </div>

    <script src="assets/js/upload.js"></script>

</body>
</html>