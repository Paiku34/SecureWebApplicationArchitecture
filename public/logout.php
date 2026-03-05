<?php

/*
 * logout.php - Terminazione sicura sessione utente
 * 
 * Distrugge sessione PHP, invalida cookie, logga evento.
 * reindirizza al login con query string (evita riavvio sessione per flash message).
 * Previene session fixation e garantisce pulizia completa stato autenticazione.
 */

declare(strict_types=1);

session_start();

require_once '../includes/authentication.php';
require_once '../includes/db.php';

// Log se loggato
if (isset($_SESSION['user_id'])) {
    log_security_event($pdo, 'LOGOUT', 'INFO', (string)$_SESSION['user_id'], [
        'username' => $_SESSION['username'] ?? 'unknown'
    ]);
}

// rigenera session ID prima di distruggere
// invalida il vecchio session id 
session_regenerate_id(true);

// Distruggi sessione
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();

// Redirect con query string (no flash message, no session restart)
header('Location: login.php?logout=success', true, 303);
exit();
?>