<div align="center">

# 🔒 Security Documentation — MusicProject

[![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![OWASP](https://img.shields.io/badge/OWASP-Top10%20Covered-red)](https://owasp.org/www-project-top-ten/)
[![Argon2ID](https://img.shields.io/badge/Hashing-Argon2ID-blueviolet)](https://www.rfc-editor.org/rfc/rfc9106)

**Version 1.0 · PHP 8.2 · MySQL 8.0 · Docker**

> Full PDF version available in [`docs/SECURITY.pdf`](docs/SECURITY.pdf)

</div>

← Back to [README](README.md)

---

## Table of Contents

1. [General Architecture](#1-general-architecture)
2. [Authentication & Session Management](#2-authentication--session-management)
3. [CSRF Protection](#3-csrf-protection)
4. [Rate Limiting](#4-rate-limiting)
5. [Input Validation & Sanitization](#5-input-validation--sanitization)
6. [Password Security](#6-password-security)
7. [Secure File Upload](#7-secure-file-upload)
8. [Secure Download & Integrity Check](#8-secure-download--integrity-check)
9. [Path Traversal Protection](#9-path-traversal-protection)
10. [HTTP Security Headers](#10-http-security-headers)
11. [Database Security](#11-database-security)
12. [Logging & Audit Trail](#12-logging--audit-trail)
13. [Password Recovery](#13-password-recovery)
14. [Admin Panel](#14-admin-panel)
15. [Maintenance & Automatic Cleanup](#15-maintenance--automatic-cleanup)
16. [Environment Configuration (Docker)](#16-environment-configuration-docker)
17. [Vulnerability Coverage Matrix](#17-vulnerability-coverage-matrix)

---

## 1. General Architecture

```
public/          ← HTTP entry points (direct browser access)
includes/        ← Shared logic (auth, DB, logger, rate limiter)
storage/
  uploads/
    audio/       ← Uploaded MP3 files (chmod 0644)
    lyrics/      ← Uploaded TXT files
  logs/          ← Security log files
```

**Core security principles applied:**

| Principle | Application |
|-----------|-------------|
| Defense in Depth | Every operation has ≥2 independent controls |
| Fail Secure | On error, access is denied (never granted) |
| Least Privilege | DB user has only the minimum permissions needed |
| Separation of Concerns | Upload form (upload.php) separate from controller (upload_control.php) |
| Security by Default | `declare(strict_types=1)` in every PHP file |

---

## 2. Authentication & Session Management

### Files: `includes/authentication.php`, `public/login.php`

### 2.1 Secure Session Configuration

Configured before `session_start()` via `ini_set()`:

| Parameter | Value | Reason |
|-----------|-------|--------|
| `use_strict_mode` | `1` | Rejects session IDs not initialized by the server |
| `cookie_httponly` | `1` | Cookie inaccessible via JavaScript (XSS mitigation) |
| `cookie_samesite` | `Lax` | Blocks cookie on cross-site requests (CSRF mitigation) |
| `cookie_secure` | `1` (prod) | Cookie transmitted only over HTTPS |
| `cookie_lifetime` | `0` | Session cookie (deleted on browser close) |
| `use_only_cookies` | `1` | Session ID via cookie only (not via URL) |
| `gc_maxlifetime` | `1800` | Garbage collection after 30 minutes of inactivity |

### 2.2 Session Validation (`validate_session()`)

Three sequential checks on every authenticated request:

1. **`user_id` present in `$_SESSION`** — if absent, redirect to login
2. **Inactivity timeout (30 minutes)** — `$_SESSION['last_activity']` updated on each request
3. **Real-time ban check** — `SELECT is_banned FROM users WHERE id = ?` on every request; a banned user is evicted on next request even with a valid session

### 2.3 IP Binding (Anti Session Hijacking)

On login: `$_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR']`

On every protected request:
```php
if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    header("Location: login.php");
    exit();
}
```

### 2.4 Session Fixation Prevention

At login, after credentials are verified:
```php
session_regenerate_id(true);  // generates new ID, deletes the old one
```

The `true` parameter deletes the old session file from the server.

### 2.5 Timing Attack Prevention (Anti Username Enumeration)

If the username does not exist in the DB, a `password_verify()` is still executed against a dummy hash with the same Argon2ID parameters (memory=64MB, time=4). This ensures the response time is identical for "username not found" and "wrong password", preventing username enumeration via timing.

---

## 3. CSRF Protection

### File: `includes/authentication.php`

### Token Generation

```php
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // 256 bits of entropy
    }
    return $_SESSION['csrf_token'];
}
```

- **Entropy:** 256 bits (32 bytes from CSPRNG)
- **Storage:** Server-side in session (not in cookie)
- **Transmission:** Hidden input in the HTML form

### Token Verification

```php
function verify_csrf_token(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}
```

`hash_equals()` is **timing-safe**: the comparison always takes the same time regardless of how many characters match, preventing timing-oracle attacks on the CSRF token.

### Separate Token for Admin Area

The admin panel uses a separate CSRF token (`admin_csrf_token`), implementing privilege separation at the CSRF level as well.

---

## 4. Rate Limiting

### File: `includes/RateLimiter.php`

### Architecture

The rate limiter is database-backed (table `rate_limits`) with a sliding time window. No Redis or Memcached required.

**Table schema:**
```sql
CREATE TABLE rate_limits (
    identifier  VARCHAR(255) PRIMARY KEY,
    action_type VARCHAR(50),
    attempts    INT DEFAULT 0,
    window_start DATETIME,
    last_attempt DATETIME
);
```

### Limits per Action

| Action | Max Attempts | Window | Scope |
|--------|-------------|--------|-------|
| `login` | 5 | 15 minutes | Per username + per IP (independent) |
| `register` | 5 | 60 minutes | Per IP |
| `upload` | 10 | 60 minutes | Per user_id |
| `download` | 10 | 60 minutes | Per user_id |
| `view_lyrics` | 1000 | 60 minutes | Per user_id (anti-scraping) |
| `password_reset` | 3 | 24 hours | Per IP |
| `change_password` | 3 | 24 hours | Per user_id |

### Dual-Layer Login Protection

Login rate limiting uses **two independent identifiers**:

- `login_ip_{IP}` — blocks brute force from a single IP (even with different usernames)
- `{username}` — blocks targeted brute force on a specific account (even from different IPs)

### Atomic Anti-Race Condition

```sql
INSERT INTO rate_limits (identifier, action_type, attempts, window_start, last_attempt)
VALUES (?, ?, 1, NOW(), NOW())
ON DUPLICATE KEY UPDATE
    attempts     = IF(window_start < DATE_SUB(NOW(), INTERVAL ? SECOND), 1, attempts + 1),
    window_start = IF(window_start < DATE_SUB(NOW(), INTERVAL ? SECOND), NOW(), window_start),
    last_attempt = NOW()
```

This atomic query prevents race conditions where two concurrent requests both increment from 0 to 1 instead of 0→1→2.

---

## 5. Input Validation & Sanitization

### Files: `includes/authentication.php`, all `public/` files

### Core Validation Functions

```php
// Checks: is string + non-empty + length ≤ max
function is_nonempty_string($value, int $max_length = 255): bool

// Normalizes username: applies whitelist /^[A-Za-z0-9_.-]{3,32}$/, returns '' if invalid
function normalize_username(string $username): string
```

### Whitelist vs Blacklist

The project uses **whitelists** (allowed characters/formats) instead of blacklists (forbidden characters):

- Username: only `[A-Za-z0-9_.-]`
- File paths: only `[a-zA-Z0-9\/_.-]`
- Free-text input (titles): `[\p{L}\p{N}\s\-_.`,!?()'"]` — Unicode letters, numbers, basic punctuation

### XSS Output Prevention

Every dynamic variable inserted into HTML uses:
```php
htmlspecialchars($value, ENT_QUOTES, 'UTF-8')
```

`ENT_QUOTES` encodes both `'` and `"`, preventing both tag injection and attribute injection.

---

## 6. Password Security

### Files: `includes/authentication.php`, `public/register.php`, `public/change_password.php`, `public/recover.php`

### Hashing Algorithm

| Parameter | Value |
|-----------|-------|
| Algorithm | Argon2ID (OWASP Recommended 2024) |
| `memory_cost` | 65536 (64 MB) |
| `time_cost` | 4 iterations |
| `threads` | 1 |

Argon2ID is resistant to GPU attacks (memory-hard) and side-channel attacks (combines Argon2i and Argon2d).

### Password Strength Scoring

Server-side algorithm (in `evaluatePasswordStrength()`) independent from the client-side JavaScript:

| Criterion | Points |
|-----------|--------|
| Length ≥12 | 20 |
| Length ≥16 | +10 |
| Lowercase letters | 15 |
| Uppercase letters | 15 |
| Numbers | 15 |
| Symbols | 20 |
| No predictable sequences (`1234`, `qwerty`, `password`) | +5 |

To register or reset a password: **score 100/100 + all categories must be present**.

### Password Policy

- Minimum length: **12 characters**
- Maximum length: **256 characters** (anti-DoS limit for Argon2ID)
- New password must be **different** from the old one (in change_password.php)

---

## 7. Secure File Upload

### File: `public/upload_control.php`

### Validation Pipeline (in order, before saving anything)

```
1. Session check + IP binding
2. CSRF token verification
3. Rate limiting (10 uploads/hour per user)
4. Title: character whitelist regex
5. validateFile(audio):
   a. UPLOAD_ERR_* check
   b. Size ≤ 10MB
   c. Extension whitelist: ['mp3']
   d. Real MIME type (finfo magic bytes): ['audio/mpeg']
6. validateFile(lyrics):
   a. UPLOAD_ERR_* check
   b. Size ≤ 1MB
   c. Extension whitelist: ['txt']
   d. Real MIME type: ['text/plain']
```

**Both files are fully validated BEFORE either is saved.** If the second file is invalid, the first is not wasted on disk.

### Secure Save Process

```
7. saveFile(audio):
   - Name: uniqid() + bin2hex(random_bytes(8)) → unpredictable
   - SHA-256 hash computed before the move
   - move_uploaded_file() (verifies is_uploaded_file() internally)
   - chmod(0644)
8. saveFile(lyrics): same process
9. INSERT in DB transaction with rollback
10. On rollback: unlink() any physical files already saved
```

### Protection Against Executable File Upload

- Extension validated (whitelist: mp3 and txt only)
- Real MIME type verified via magic bytes (not the browser's `Content-Type`)
- `chmod 0644` → no execute bit
- Files stored in `storage/uploads/` (not a web root directory with PHP execution enabled)

---

## 8. Secure Download & Integrity Check

### Files: `public/download.php`, `public/view_lyrics.php`

### Premium Access Control

```php
if ($media['is_premium'] && !$currentUser['is_premium']) {
    // → HTTP 403 + log WARNING
}
```

### SHA-256 Integrity Check

At download time, the file on disk is re-hashed and compared against the hash stored in the DB at upload time:

```php
$current_hash = hash_file('sha256', $requested_path);
if ($current_hash !== $media['audio_hash']) {
    // → HTTP 500 + log CRITICAL (possible tampering)
}
```

### MIME Re-validation at Download

Even if the file passed the upload check, `finfo_file()` re-verifies the magic bytes at download time. This blocks scenarios where a file was manually replaced on the server.

### Secure Download Headers

```
Content-Type: audio/mpeg
Content-Disposition: attachment; filename="..."
X-Content-Type-Options: nosniff   ← prevents browser MIME sniffing
Cache-Control: no-cache
```

The filename in `Content-Disposition` is sanitized with `preg_replace` to prevent header injection.

---

## 9. Path Traversal Protection

### Applied in: `download.php`, `view_lyrics.php`, `admin.php` (delete media)

### Double Check

**CHECK A — Regex on the DB path:**
```php
if (strpos($path, '..') !== false || preg_match('/[^a-zA-Z0-9\/_.-]/', $path)) {
    // → 400 Bad Request + log
}
```

**CHECK B — Canonical path with `realpath()`:**
```php
$storage_dir    = realpath(__DIR__ . '/../storage');
$requested_path = realpath($storage_dir . '/' . $path);

if (!$requested_path || strpos($requested_path, $storage_dir) !== 0) {
    // → 404 Not Found + log
}
```

`realpath()` resolves symlinks and `../` sequences. Even if a tampered path survived CHECK A, `strpos($resolved, $storage_dir) !== 0` would block it.

**Example:**
- Input: `audio/../../etc/passwd`
- After `realpath()`: `/etc/passwd`
- `strpos('/etc/passwd', '/var/www/storage')` → `false` → BLOCKED

---

## 10. HTTP Security Headers

### File: `includes/authentication.php` → `set_security_headers()`

| Header | Value | Protection |
|--------|-------|------------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` | XSS via script injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Sensitive URL leakage via Referer |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTPS downgrade attacks |
| `X-XSS-Protection` | `1; mode=block` | XSS in legacy browsers |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Browser feature policy |

---

## 11. Database Security

### File: `includes/db.php`

### PDO Configuration

| Option | Value | Rationale |
|--------|-------|-----------|
| `ATTR_EMULATE_PREPARES` | `false` | Native driver prepared statements (not emulated): structural query/data separation |
| `ERRMODE` | `EXCEPTION` | DB errors → PHP exceptions (no silent failures) |
| `DEFAULT_FETCH_MODE` | `ASSOC` | Associative arrays (no opaque numeric indexes) |
| `ATTR_PERSISTENT` | `false` | No persistent connections (avoids inherited state) |
| SQL `SET NAMES utf8mb4` | — | Explicit charset in handshake |
| SQL mode | `STRICT_ALL_TABLES` | Rejects invalid values (no silent truncation) |

### SQL Injection Protection

**100% prepared statements.** No query uses string concatenation with user input. Example:

```php
// ✓ Safe
$stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
$stmt->execute([$username]);

// ✗ NEVER used in this codebase
$pdo->query("SELECT id FROM users WHERE username = '$username'");
```

### DB Credentials

No hardcoded credentials. All read from Docker environment variables:
```php
getenv('MYSQL_HOST')     // Database host
getenv('MYSQL_USER')     // DB user
getenv('MYSQL_PASSWORD') // DB password
getenv('MYSQL_DATABASE') // Database name
```

---

## 12. Logging & Audit Trail

### File: `includes/SecurityLogger.php`

### Dual-Channel Architecture

| Channel | Condition | Format | Location |
|---------|-----------|--------|----------|
| File | Always | JSON one-line | `storage/logs/security.log` |
| Database | WARNING and CRITICAL only | SQL record | Table `security_logs` |

**Rationale:**
- The file persists even if the DB is down or corrupted
- The DB allows analytical queries and alerting (e.g. "all WARNINGs from the last 24h")

### Log Levels

| Level | When |
|-------|------|
| `INFO` | Successful login, completed download, lyrics view |
| `WARNING` | Failed login, CSRF violation, rate limit exceeded, ban attempt, missing premium |
| `CRITICAL` | Integrity check failed, path traversal detected |

### Automatic Log Rotation

When `security.log` exceeds **10MB**, it is renamed to `security.log.old` and a new empty file is created. Managed by `SecurityLogger::rotateLogs()`.

### Logged Data

Each event contains: timestamp, level, event type, user identifier, IP address, User-Agent, contextual data (e.g. `username_attempted`, `file_id`, expected hash vs found hash).

**CSRF tokens in logs:** Truncated to 16 characters for forensic utility without exposing the full token.

---

## 13. Password Recovery

### File: `public/recover.php`

### 3-Phase Flow

```
PHASE A: POST {identifier}
  → Rate limit: 3 requests/day per IP
  → Generate token: bin2hex(random_bytes(32)) = 64 hex chars = 256 bits
  → Store in DB: hash('sha256', $token) — NEVER the plaintext token
  → Expiry: 30 minutes
  → Send email with reset URL (PHPMailer)
  → IDENTICAL response whether user exists or not (anti-enumeration)

PHASE B: GET ?token=...
  → Validate format: /^[a-f0-9]{64}$/
  → Retrieve SHA-256 hash of the token from DB
  → Verify: not expired (expires_at > NOW()) + not used (used_at IS NULL)
  → Generate separate CSRF token for the reset form

PHASE C: POST {token} + {new_password}
  → CSRF check (separate token for this phase)
  → BEGIN TRANSACTION + SELECT ... FOR UPDATE (prevents race condition)
  → Re-verify token (double check for atomicity)
  → New password strength validation (score 100/100)
  → UPDATE users SET password_hash = ?
  → UPDATE password_resets SET used_at = NOW() (one-time use)
  → COMMIT
```

### Token Security

| Property | Implementation |
|----------|---------------|
| Entropy | 256 bits (random_bytes) |
| Storage | SHA-256 hash of the token (not plaintext) |
| One-time use | `used_at` set after use |
| Expiry | 30 minutes |
| Anti-race | `SELECT ... FOR UPDATE` inside transaction |

---

## 14. Admin Panel

### File: `public/admin.php`

### Access Controls

1. **Verify `is_admin=1` in session**
2. **IP binding** — same check as all other protected files
3. **Re-read `is_admin` from DB on every request** — a demoted admin is evicted immediately

### Privileged Action Protections

| Action | Additional Protection |
|--------|----------------------|
| `toggle_ban` | Blocks self-ban + banning other admins |
| `toggle_admin` | Blocks self-demotion |
| `delete_user` | Deletes physical files first (with path traversal check), then DB record |
| `delete_media` | `realpath()` + `strpos()` before `unlink()` |
| `unblock_user` | `action_type` validated against whitelist of existing action types |

### Separate Admin CSRF

Every admin form includes an `admin_csrf_token` generated independently. It cannot be reused in normal user contexts (privilege separation).

---

## 15. Maintenance & Automatic Cleanup

### File: `includes/maintenance.php`

**Strategy:** 1% probability per HTTP request (`rand(1,100) === 1`) → no cron job required.

| Operation | Threshold |
|-----------|-----------|
| Clean expired rate_limits | > action type window |
| Clean used/expired password_resets | > 7 days |
| Rotate security.log | > 10MB |
| Clean security_logs DB records | > 90 days |

---

## 16. Environment Configuration (Docker)

### Files: `Dockerfile`, `docker-compose.yml`

- **DB credentials:** Only via Docker environment variables (`MYSQL_*`)
- **No credentials in VCS:** `.env` is not committed; `.gitignore` excludes `.env`, `vendor/`, all upload files and logs
- **MailHog:** Local mail server for development; in production replace with real SMTP via env vars `MAIL_HOST`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASS`
- **`APP_ENV`:** `development` enables additional debug logs; set to `production` for live deployments

---

## 17. Vulnerability Coverage Matrix

| Vulnerability (OWASP Top 10) | Mitigation |
|------------------------------|------------|
| **A01 — Broken Access Control** | `validate_session()` + IP binding + real-time `is_admin` check + premium check |
| **A02 — Cryptographic Failures** | Argon2ID with OWASP parameters, SHA-256 for integrity, `random_bytes(32)` for tokens, HTTPS-only cookies |
| **A03 — Injection (SQL)** | 100% PDO prepared statements, `ATTR_EMULATE_PREPARES=false` |
| **A03 — Injection (XSS)** | `htmlspecialchars(ENT_QUOTES)` on all output, CSP header |
| **A04 — Insecure Design** | Form/controller separation, dual-channel logging, fail-secure, double path traversal check |
| **A05 — Security Misconfiguration** | Full security headers, `strict_types`, `STRICT_ALL_TABLES`, no hardcoded credentials |
| **A06 — Vulnerable Components** | Dependencies via Composer (PHPMailer), independently updatable |
| **A07 — Auth Failures** | Dual-layer rate limiting, session fixation prevention, timing attack prevention, real-time ban check |
| **A08 — Software Integrity** | SHA-256 `hash_file` on upload + verification at download, `move_uploaded_file` |
| **A09 — Logging Failures** | Dual-channel logging (file + DB), automatic rotation, CRITICAL for integrity violations |
| **A10 — SSRF** | No outbound HTTP requests from the application (except PHPMailer to MailHog/local SMTP) |

### Additional Vulnerabilities Covered

| Vulnerability | Mitigation |
|---------------|------------|
| **CSRF** | 256-bit token + `hash_equals()` timing-safe, `SameSite=Lax` cookie |
| **Session Hijacking** | IP binding + `session_regenerate_id(true)` on login |
| **Session Fixation** | `session_regenerate_id(true)` + delete old session |
| **Brute Force** | Rate limiting 5/15min per username + 5/15min per IP |
| **User Enumeration** | Identical response for non-existent username / wrong password (login and reset) |
| **Path Traversal** | Double check: regex whitelist + `realpath()` boundary |
| **File Upload Bypass** | MIME magic bytes check (`finfo`) independent from extension |
| **Malicious File Execution** | `chmod 0644`, extension and MIME in whitelist, storage outside PHP-exec path |
| **Account Takeover via Reset** | One-time token + 30min expiry + stored as SHA-256 hash |
| **Privilege Escalation** | `is_admin` reloaded from DB on every admin request, real-time ban check |
| **Clickjacking** | `X-Frame-Options: DENY` |
| **MIME Sniffing** | `X-Content-Type-Options: nosniff` |
| **Cache Poisoning** | `Cache-Control: no-store` on authenticated/premium content |
| **DoS via Hashing** | Max 256 chars per password (Argon2ID cost limit) |
| **Race Condition Reset** | `SELECT ... FOR UPDATE` in transaction for reset token |
