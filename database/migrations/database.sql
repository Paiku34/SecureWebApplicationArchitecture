-- Tabella Utenti
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_premium BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    is_banned BOOLEAN DEFAULT FALSE,
    total_uploads INT DEFAULT 0,
    total_downloads_received INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- Tabella Media con colonne hash per integrity check
CREATE TABLE IF NOT EXISTS media (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    audio_path VARCHAR(255) NULL,
    audio_hash VARCHAR(64) NULL,      -- Hash SHA-256 per verifica integrità audio
    lyrics_path VARCHAR(255) NULL,
    lyrics_hash VARCHAR(64) NULL,     -- Hash SHA-256 per verifica integrità testo
    is_premium BOOLEAN DEFAULT FALSE,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_media_user_premium (user_id, is_premium),
    INDEX idx_media_uploaded (uploaded_at DESC)
) ENGINE=InnoDB;

-- Tabella Rate Limiting per controllo abusi
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL, 
    attempt_count INT DEFAULT 1,
    is_blocked TINYINT(1) DEFAULT 0,
    first_attempt DATETIME NOT NULL,
    last_attempt DATETIME NOT NULL,
    UNIQUE KEY idx_identifier_action (identifier, action_type),
    INDEX idx_last_attempt (last_attempt)
) ENGINE=InnoDB;

-- Tabella Security Logs per eventi critici
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity ENUM('INFO', 'WARNING', 'CRITICAL') NOT NULL,
    user_id VARCHAR(50) DEFAULT 'anonymous',
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    request_uri TEXT,
    context JSON,
    created_at DATETIME NOT NULL,
    INDEX idx_severity_created (severity, created_at),
    INDEX idx_event_type (event_type),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- Tabella Password Resets per gestione sicura dei reset delle password
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARBINARY(32) NOT NULL,      -- SHA-256 binario
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_token (token_hash),
    INDEX idx_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;


