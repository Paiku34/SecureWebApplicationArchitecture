<?php
/*
 * index.php - Entry point applicazione
 * 
 * Redirige utenti autenticati a dashboard, non autenticati a login.
 * Esegue cleanup automatico 1% delle richieste, filtra bot per evitare log flooding.
 */

// 1. Inizializzazione con gestione errori
try {
    require_once '../includes/authentication.php';
    require_once '../includes/SecurityLogger.php';
    require_once '../includes/db.php';
    $securityLogger = new SecurityLogger($pdo);
    
    // cleanup automatico (1% probabilità)
    maybe_run_maintenance($pdo);
    
} catch (Exception $e) {
    error_log("[CRITICAL] index.php startup failed: " . $e->getMessage());
    http_response_code(500);
    exit("Servizio temporaneamente non disponibile. Riprova tra qualche minuto.");
}

// headers anti-cache
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// routing basato su autenticazione
if (!isset($_SESSION['user_id'])) {
    // filtra bot comuni per evitare log flooding
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $common_bots = ['Googlebot', 'bingbot', 'Yahoo! Slurp', 'DuckDuckBot', 'Baiduspider'];
    $is_bot = false;
    
    foreach ($common_bots as $bot) {
        if (stripos($user_agent, $bot) !== false) {
            $is_bot = true;
            break;
        }
    }
    
    // logga solo utenti reali
    if (!$is_bot) {
        $securityLogger->log('homepage_access_anonymous', 'INFO', [
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $user_agent
        ]);
    }
    
    header('Location: login.php');
    exit();
} else {
    // utente autenticato va in dashboard
    header('Location: dashboard.php');
    exit();
}