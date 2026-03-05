# Documentazione Sicurezza — MusicProject

> Versione: 1.0 | PHP 8.x | MariaDB | Docker

---

## Indice

1. [Architettura Generale](#1-architettura-generale)
2. [Autenticazione e Gestione Sessioni](#2-autenticazione-e-gestione-sessioni)
3. [Protezione CSRF](#3-protezione-csrf)
4. [Rate Limiting](#4-rate-limiting)
5. [Validazione e Sanitizzazione Input](#5-validazione-e-sanitizzazione-input)
6. [Sicurezza Password](#6-sicurezza-password)
7. [Upload Sicuro dei File](#7-upload-sicuro-dei-file)
8. [Download Sicuro e Integrity Check](#8-download-sicuro-e-integrity-check)
9. [Protezione Path Traversal](#9-protezione-path-traversal)
10. [HTTP Security Headers](#10-http-security-headers)
11. [Sicurezza Database](#11-sicurezza-database)
12. [Logging e Audit Trail](#12-logging-e-audit-trail)
13. [Recovery Password](#13-recovery-password)
14. [Pannello Admin](#14-pannello-admin)
15. [Manutenzione e Cleanup Automatico](#15-manutenzione-e-cleanup-automatico)
16. [Configurazione Ambiente (Docker)](#16-configurazione-ambiente-docker)
17. [Matrice delle Vulnerabilità Coperte](#17-matrice-delle-vulnerabilit%C3%A0-coperte)

---

## 1. Architettura Generale

```
public/          ← Entry point HTTP (accesso diretto del browser)
includes/        ← Logica condivisa (autenticazione, DB, logger, rate limiter)
storage/
  uploads/
    audio/       ← File MP3 caricati (fuori dalla document root non è necessario, chmod 0644)
    lyrics/      ← File TXT caricati
  logs/          ← Log sicurezza su file
```

**Principi fondamentali applicati:**

| Principio | Applicazione |
|-----------|-------------|
| Defense in Depth | Ogni operazione ha ≥2 controlli indipendenti |
| Fail Secure | In caso di errore, accesso negato (non permesso) |
| Least Privilege | Il DB non ha UPDATE/DELETE su tabelle non necessarie per ogni query |
| Separation of Concerns | Form (upload.php) separato dal controller (upload_control.php) |
| Security by Default | `declare(strict_types=1)` in tutti i file PHP |

---

## 2. Autenticazione e Gestione Sessioni

### File: `includes/authentication.php`, `public/login.php`

### 2.1 Configurazione Sessione Sicura

Configurata prima di `session_start()` tramite `ini_set()`:

| Parametro | Valore | Motivo |
|-----------|--------|--------|
| `use_strict_mode` | `1` | Rifiuta session ID non inizializzati dal server |
| `cookie_httponly` | `1` | Cookie non accessibile via JavaScript (mitigazione XSS) |
| `cookie_samesite` | `Lax` | Blocca invio cookie su richieste cross-site (mitigazione CSRF) |
| `cookie_secure` | `1` (prod) | Cookie trasmesso solo su HTTPS |
| `cookie_lifetime` | `0` | Cookie di sessione (eliminato alla chiusura del browser) |
| `use_only_cookies` | `1` | Session ID solo via cookie (non via URL) |
| `gc_maxlifetime` | `1800` | Garbage collection dopo 30 minuti di inattività |

### 2.2 Validazione Sessione (`validate_session()`)

Tre controlli sequenziali ad ogni richiesta autenticata:

1. **Presenza `user_id` in `$_SESSION`** — se assente, redirect a login
2. **Timeout inattività (30 minuti)** — `$_SESSION['last_activity']` aggiornato ad ogni richiesta
3. **Ban check real-time** — query `SELECT is_banned FROM users WHERE id = ?` ad ogni richiesta;
   un utente bannato viene espulso alla richiesta successiva anche se ha una sessione valida

### 2.3 IP Binding (Anti Session Hijacking)

All'accesso: `$_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR']`

Ad ogni richiesta protetta:
```php
if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    header("Location: login.php");
    exit();
}
```

### 2.4 Session Fixation Prevention

Al momento del login, dopo aver verificato le credenziali:
```php
session_regenerate_id(true);  // genera nuovo ID, elimina il vecchio
```

Il parametro `true` elimina il vecchio file di sessione dal server.

### 2.5 Timing Attack Prevention (Anti User Enumeration via Timing)

Se l'username non esiste nel DB, viene eseguito comunque un `password_verify()` su un hash dummy con gli stessi parametri Argon2ID (memory=64MB, time=4). Questo garantisce che il tempo di risposta sia identico per "username non esiste" e "password sbagliata", impedendo l'enumerazione degli username via timing.

---

## 3. Protezione CSRF

### File: `includes/authentication.php`

### Generazione Token

```php
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // 256 bit di entropia
    }
    return $_SESSION['csrf_token'];
}
```

- **Entropia:** 256 bit (32 byte casuali da CSPRNG)
- **Storage:** In sessione lato server (non nel cookie)
- **Transmission:** Hidden input nel form HTML

### Verifica Token

```php
function verify_csrf_token(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}
```

`hash_equals()` è **timing-safe**: il confronto impiega sempre lo stesso tempo indipendentemente da quanti caratteri corrispondono, prevenendo timing-oracle attack sul token CSRF.

### Token Separati per Area Admin

Il pannello admin usa un token CSRF separato (`admin_csrf_token`) dal token utente standard, implementando la separazione dei privilegi anche a livello CSRF.

---

## 4. Rate Limiting

### File: `includes/RateLimiter.php`

### Architettura

Il rate limiter è basato su database (tabella `rate_limits`) con finestra temporale scorrevole. Non richiede Redis o Memcached.

**Schema tabella:**
```sql
CREATE TABLE rate_limits (
    identifier  VARCHAR(255) PRIMARY KEY,
    action_type VARCHAR(50),
    attempts    INT DEFAULT 0,
    window_start DATETIME,
    last_attempt DATETIME
);
```

### Configurazione Limiti per Azione

| Azione | Max Tentativi | Finestra | Scope |
|--------|--------------|---------|-------|
| `login` | 5 | 15 minuti | Per username + per IP separati |
| `register` | 5 | 60 minuti | Per IP |
| `upload` | 10 | 60 minuti | Per user_id |
| `download` | 10 | 60 minuti | Per user_id |
| `view_lyrics` | 1000 | 60 minuti | Per user_id (anti-scraping) |
| `password_reset` | 3 | 24 ore | Per IP |
| `change_password` | 3 | 24 ore | Per user_id |

### Doppio Layer Login

Il login applica rate limiting su **due identificatori indipendenti**:

- `login_ip_{IP}` — blocca brute force da uno stesso IP (anche con username diversi)
- `{username}` — blocca targeted brute force su uno specifico account (anche da IP diversi)

### Atomicità Anti-Race Condition

```sql
INSERT INTO rate_limits (identifier, action_type, attempts, window_start, last_attempt)
VALUES (?, ?, 1, NOW(), NOW())
ON DUPLICATE KEY UPDATE
    attempts     = IF(window_start < DATE_SUB(NOW(), INTERVAL ? SECOND), 1, attempts + 1),
    window_start = IF(window_start < DATE_SUB(NOW(), INTERVAL ? SECOND), NOW(), window_start),
    last_attempt = NOW()
```

Questa query atomica previene race condition in cui due richieste simultanee incrementino da 0 a 1 separatamente invece di 0→1→2.

---

## 5. Validazione e Sanitizzazione Input

### File: `includes/authentication.php`, tutti i file `public/`

### Funzioni di Validazione Base

```php
// Verifica: è stringa + non vuota + lunghezza ≤ max
function is_nonempty_string($value, int $max_length = 255): bool

// Normalizza username: applica whitelist /^[A-Za-z0-9_.-]{3,32}$/, ritorna '' se invalido
function normalize_username(string $username): string
```

### Whitelist vs Blacklist

Il progetto usa **whitelist** (elenco di caratteri/formati **ammessi**) invece di blacklist (elenco di caratteri **vietati**):

- Username: solo `[A-Za-z0-9_.-]`
- Path file: solo `[a-zA-Z0-9\/_.-]`
- Extra input (titoli): `[\p{L}\p{N}\s\-_.`,!?()'"]` — lettere Unicode, numeri, punteggiatura base

### Prevensione XSS Output

Ogni variabile dinamica inserita nell'HTML usa:
```php
htmlspecialchars($value, ENT_QUOTES, 'UTF-8')
```

`ENT_QUOTES` converte sia `'` che `"`, prevenendo sia tag injection che attribute injection.

---

## 6. Sicurezza Password

### File: `includes/authentication.php`, `public/register.php`, `public/change_password.php`, `public/recover.php`

### Algoritmo di Hashing

| Parametro | Valore |
|-----------|--------|
| Algoritmo | Argon2ID (OWASP Recommended 2024) |
| `memory_cost` | 65536 (64 MB) |
| `time_cost` | 4 iterazioni |
| `threads` | 1 |

Argon2ID è resistente a GPU attacks (memory-hard) e side-channel attacks (combina Argon2i e Argon2d).

### Password Strength Scoring

Algoritmo server-side (in `evaluatePasswordStrength()`) indipendente dal JavaScript client-side:

| Criterio | Punti |
|---------|-------|
| Lunghezza ≥12 | 20 |
| Lunghezza ≥16 | +10 |
| Lettere minuscole | 15 |
| Lettere maiuscole | 15 |
| Numeri | 15 |
| Simboli | 20 |
| Sequenze prevedibili assenti (`1234`, `qwerty`, `password`) | +5 |

Per registrarsi o resettare la password: **score 100/100 + tutte le categorie presenti**.

### Policy Password

- Lunghezza minima: **12 caratteri**
- Lunghezza massima: **256 caratteri** (limite anti-DoS per Argon2ID)
- Nuova password deve essere **diversa** dalla vecchia (in change_password.php)

---

## 7. Upload Sicuro dei File

### File: `public/upload_control.php`

### Pipeline di Validazione (in ordine, senza salvare)

```
1. Verifica sessione + IP binding
2. Verifica CSRF token
3. Rate limiting (10 upload/ora per utente)
4. Titolo: regex whitelist caratteri
5. validateFile(audio):
   a. UPLOAD_ERR_* check
   b. Dimensione ≤ 10MB
   c. Estensione whitelist: ['mp3']
   d. MIME type reale (finfo magic bytes): ['audio/mpeg']
6. validateFile(lyrics):
   a. UPLOAD_ERR_* check
   b. Dimensione ≤ 1MB
   c. Estensione whitelist: ['txt']
   d. MIME type reale: ['text/plain']
```

**Entrambi i file vengono validati PRIMA di salvarne uno.** Se il secondo file è invalido, il primo non viene sprecato su disco.

### Salvataggio Sicuro

```
7. saveFile(audio):
   - Nome: uniqid() + bin2hex(random_bytes(8)) → non predicibile
   - Hash SHA-256 calcolato prima del move
   - move_uploaded_file() (verifica is_uploaded_file internamente)
   - chmod(0644)
8. saveFile(lyrics): stesso processo
9. INSERT in transazione DB con rollback
10. Se rollback: unlink() dei file fisici già salvati
```

### Protezione contro Upload di File Eseguibili

- Estensione validata (whitelist: solo mp3 e txt)
- MIME type reale verificato tramite magic bytes (non il `Content-Type` del browser)
- `chmod 0644` → nessun bit di esecuzione
- I file sono in `storage/uploads/` (non in una directory servita come web root con PHP abilitato)

---

## 8. Download Sicuro e Integrity Check

### File: `public/download.php`, `public/view_lyrics.php`

### Controllo Premium

```php
if ($media['is_premium'] && !$currentUser['is_premium']) {
    // → HTTP 403 + log WARNING
}
```

### Integrity Check SHA-256

Al momento del download, il file su disco viene re-hashato e confrontato con l'hash salvato nel DB al momento dell'upload:

```php
$current_hash = hash_file('sha256', $requested_path);
if ($current_hash !== $media['audio_hash']) {
    // → HTTP 500 + log CRITICAL (possibile manomissione)
}
```

### Ri-validazione MIME al Download

Anche se il file ha passato il check all'upload, `finfo_file()` ri-verifica i magic bytes al momento del download. Blocca scenari in cui un file sia stato sostituito manualmente sul server.

### Headers Download Sicuri

```
Content-Type: audio/mpeg
Content-Disposition: attachment; filename="..."
X-Content-Type-Options: nosniff   ← impedisce MIME sniffing del browser
Cache-Control: no-cache
```

Il filename nel `Content-Disposition` è sanitizzato con `preg_replace` per prevenire header injection.

---

## 9. Protezione Path Traversal

### Applicato in: `download.php`, `view_lyrics.php`, `admin.php` (delete media)

### Doppio Check

**CHECK A — Regex sul path dal DB:**
```php
if (strpos($path, '..') !== false || preg_match('/[^a-zA-Z0-9\/_.-]/', $path)) {
    // → 400 Bad Request + log
}
```

**CHECK B — Canonical path con `realpath()`:**
```php
$storage_dir    = realpath(__DIR__ . '/../storage');
$requested_path = realpath($storage_dir . '/' . $path);

if (!$requested_path || strpos($requested_path, $storage_dir) !== 0) {
    // → 404 Not Found + log
}
```

`realpath()` risolve simlink e sequenze `../`. Anche se un path manomesso sopravvivesse al CHECK A, `strpos($resolved, $storage_dir) !== 0` lo bloccherebbe.

**Esempio:**
- Input: `audio/../../etc/passwd`
- Dopo `realpath()`: `/etc/passwd`
- `strpos('/etc/passwd', '/var/www/storage')` → `false` → BLOCCATO

---

## 10. HTTP Security Headers

### File: `includes/authentication.php` → `set_security_headers()`

| Header | Valore | Protezione |
|--------|--------|-----------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` | XSS via script injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Leak URL sensibili via Referer |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade HTTPS → HTTP |
| `X-XSS-Protection` | `1; mode=block` | XSS legacy (browser datati) |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Feature policy |

---

## 11. Sicurezza Database

### File: `includes/db.php`

### Configurazione PDO

| Opzione | Valore | Motivazione |
|---------|--------|------------|
| `ATTR_EMULATE_PREPARES` | `false` | Prepared statements nativi del driver (non emulati): separazione strutturale query/dati |
| `ERRMODE` | `EXCEPTION` | Errori DB → eccezioni PHP (nessun silent failure) |
| `DEFAULT_FETCH_MODE` | `ASSOC` | Array associativi (no indici numerici opachi) |
| `ATTR_PERSISTENT` | `false` | No connessioni persistenti (evita stato ereditato) |
| SQL `SET NAMES utf8mb4` | — | Charset esplicito nel handshake |
| SQL mode | `STRICT_ALL_TABLES` | Rifiuta valori invalidi (no troncamento silenzioso) |

### Protezione da SQL Injection

**100% prepared statements.** Nessuna query usa concatenazione di stringhe con input utente. Esempio:

```php
// ✓ Sicuro
$stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
$stmt->execute([$username]);

// ✗ MAI usato nel codebase
$pdo->query("SELECT id FROM users WHERE username = '$username'");
```

### Credenziali DB

Nessuna credenziale hardcoded. Tutte lette da variabili d'ambiente Docker:
```php
getenv('MYSQL_HOST')     // Host database
getenv('MYSQL_USER')     // Utente DB
getenv('MYSQL_PASSWORD') // Password DB
getenv('MYSQL_DATABASE') // Nome database
```

---

## 12. Logging e Audit Trail

### File: `includes/SecurityLogger.php`

### Architettura Dual-Channel

| Canale | Condizione | Formato | Posizione |
|--------|-----------|---------|----------|
| File | Sempre | JSON one-line | `storage/logs/security.log` |
| Database | Solo WARNING e CRITICAL | Record SQL | Tabella `security_logs` |

**Rationale dual-channel:**
- Il file log persiste anche se il DB è down o corrotto
- Il DB permette query analitiche e alerting (es. "tutti i WARNING dell'ultimo giorno")

### Livelli Log

| Livello | Quando |
|---------|--------|
| `INFO` | Login riuscito, download completato, view lyrics |
| `WARNING` | Login fallito, CSRF violation, rate limit superato, ban attempt, missing premium |
| `CRITICAL` | Integrity check fallito, path traversal rilevato |

### Rotazione Log Automatica

Quando `security.log` supera **10MB**, viene rinominato in `security.log.old` (backup) e si ricomincia con un file vuoto. Gestito da `SecurityLogger::rotateLogs()`.

### Dati Loggati

Ogni evento contiene: timestamp, livello, tipo evento, user identifier, indirizzo IP, User-Agent, dati contestuali (es. `username_attempted`, `file_id`, hash atteso vs hash trovato).

**Token CSRF nei log:** Vengono troncati a 16 caratteri per utilità forense senza esporre il token intero.

---

## 13. Recovery Password

### File: `public/recover.php`

### Flusso a 3 Fasi

```
FASE A: POST {identifier}
  → Rate limit: 3 richieste/giorno per IP
  → Genera token: bin2hex(random_bytes(32)) = 64 hex char = 256 bit
  → Salva nel DB: hash('sha256', $token) — MAI il token in chiaro
  → Scadenza: 30 minuti
  → Invia email con URL di reset (PHPMailer)
  → Risposta IDENTICA se utente esiste o no (anti-enumeration)

FASE B: GET ?token=...
  → Valida formato: /^[a-f0-9]{64}$/
  → Recupera hash SHA-256 del token dal DB
  → Verifica: non scaduto (expires_at > NOW()) + non usato (used_at IS NULL)
  → Genera CSRF separato per il form di reset

FASE C: POST {token} + {new_password}
  → CSRF check (token separato per questa fase)
  → BEGIN TRANSACTION + SELECT ... FOR UPDATE (previene race condition)
  → Ri-verifica token (doppio check per atomicità)
  → Validazione strength nuova password (score 100/100)
  → UPDATE users SET password_hash = ?
  → UPDATE password_resets SET used_at = NOW() (one-time use)
  → COMMIT
```

### Sicurezza Token

| Proprietà | Implementazione |
|-----------|----------------|
| Entropia | 256 bit (random_bytes) |
| Archiviazione | SHA-256 del token (non plaintext) |
| One-time | `used_at` settato dopo l'uso |
| Scadenza | 30 minuti |
| Anti Race | `SELECT ... FOR UPDATE` in transazione |

---

## 14. Pannello Admin

### File: `public/admin.php`

### Controlli di Accesso

1. **Verifica `is_admin=1` in sessione**
2. **IP binding** — stessa verifica degli altri file protetti
3. **Rilettura `is_admin` dal DB ad ogni richiesta** — un admin degradato viene espulso subito

### Protezioni Azioni Privilegiate

| Azione | Protezione aggiuntiva |
|--------|----------------------|
| `toggle_ban` | Blocca auto-ban + ban di altri admin |
| `toggle_admin` | Blocca auto-demotion |
| `delete_user` | Cancella prima i file fisici (con path traversal check), poi il record DB |
| `delete_media` | `realpath()` + `strpos()` prima di `unlink()` |
| `unblock_user` | `action_type` validato contro whitelist degli action type esistenti |

### CSRF Admin Separato

Ogni form admin include un token `admin_csrf_token` generato separatamente. Non è riutilizzabile in contesti utente normale (separazione privilegi).

---

## 15. Manutenzione e Cleanup Automatico

### File: `includes/maintenance.php`

**Strategia:** 1% di probabilità per ogni richiesta HTTP (`rand(1,100) === 1`) → nessun cron job richiesto.

| Operazione | Soglia |
|-----------|--------|
| Pulizia rate_limits scaduti | > finestra dell'action type |
| Pulizia password_resets usati/scaduti | > 7 giorni |
| Rotazione security.log | > 10MB |
| Pulizia security_logs DB | > 90 giorni |

---

## 16. Configurazione Ambiente (Docker)

### File: `Dockerfile`, `docker-compose.yml`

- **Credenziali DB:** Solo via variabili d'ambiente Docker (`MYSQL_*`)
- **Nessuna credenziale in VCS:** `.env` non committato; credenziali solo in `docker-compose.yml` (da aggiungere a `.gitignore` in produzione)
- **MailHog:** Mail server locale per lo sviluppo; in produzione sostituire con SMTP reale via env vars `MAIL_HOST`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASS`
- **`APP_ENV`:** `development` abilita log di debug aggiuntivi; in produzione impostare a `production`

---

## 17. Matrice delle Vulnerabilità Coperte

| Vulnerabilità (OWASP Top 10) | Mitigazione implementata |
|------------------------------|--------------------------|
| **A01 — Broken Access Control** | validate_session() + IP binding + is_admin check real-time + premium check |
| **A02 — Cryptographic Failures** | Argon2ID con parametri OWASP, SHA-256 per integrity, random_bytes(32) per token, HTTPS-only cookies |
| **A03 — Injection (SQL)** | 100% prepared statements PDO, ATTR_EMULATE_PREPARES=false |
| **A03 — Injection (XSS)** | htmlspecialchars(ENT_QUOTES) su tutto l'output, CSP header |
| **A04 — Insecure Design** | Separazione form/controller, dual-channel logging, fail-secure, double check path traversal |
| **A05 — Security Misconfiguration** | Security headers completi, strict_types, STRICT_ALL_TABLES, no credenziali hardcoded |
| **A06 — Vulnerable Components** | Dipendenze via Composer (PHPMailer), aggiornabili autonomamente |
| **A07 — Auth Failures** | Rate limiting dual-layer, session fixation prevention, timing attack prevention, ban check real-time |
| **A08 — Software Integrity** | SHA-256 hash_file su upload + verify al download, move_uploaded_file |
| **A09 — Logging Failures** | Dual-channel logging (file + DB), rotazione automatica, CRITICAL per integrity violations |
| **A10 — SSRF** | Nessuna richiesta HTTP outbound dall'applicazione (eccetto PHPMailer a MailHog/SMTP locale) |

### Ulteriori Vulnerabilità Coperte

| Vulnerabilità | Mitigazione |
|---------------|------------|
| **CSRF** | Token 256-bit + hash_equals() timing-safe, SameSite=Lax cookie |
| **Session Hijacking** | IP binding + session_regenerate_id(true) al login |
| **Session Fixation** | session_regenerate_id(true) + delete old session |
| **Brute Force** | Rate limiting 5/15min per username + 5/15min per IP |
| **User Enumeration** | Risposta identica per username inesistente/password sbagliata (login e reset) |
| **Path Traversal** | Double check: regex whitelist + realpath() boundary |
| **File Upload Bypass** | MIME magic bytes check (finfo) indipendente dall'estensione |
| **Malicious File Execution** | chmod 0644, estensione e MIME in whitelist, storage fuori da PHP-exec path |
| **Account Takeover via Reset** | Token one-time + scadenza 30min + archiviazione come hash SHA-256 |
| **Privilege Escalation** | is_admin ricaricato dal DB ad ogni richiesta admin, ban check real-time |
| **Clickjacking** | X-Frame-Options: DENY |
| **MIME Sniffing** | X-Content-Type-Options: nosniff |
| **Cache Poisoning** | Cache-Control: no-store su contenuti autenticati/premium |
| **DoS via Hashing** | Max 256 char per password (limite Argon2ID cost) |
| **Race Condition Reset** | SELECT ... FOR UPDATE in transazione per token reset |
