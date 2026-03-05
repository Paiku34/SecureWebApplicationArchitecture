<div align="center">

# 🎵 MusicProject

**A hardened PHP web application built around security-first principles.**  
Upload, manage and share music & lyrics — without compromising on protection.

[![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Apache](https://img.shields.io/badge/Apache-2.4-D22128?logo=apache&logoColor=white)](https://httpd.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top10%20Covered-red?logo=owasp&logoColor=white)](SECURITY.md)

<br/>

> ⚠️ **This is a security-focused learning project** — every feature is documented with the *why*, not just the *how*.

<br/>

![Demo](docs/demo.gif)

</div>

---

## ✨ Features

| Category | Details |
|----------|---------|
| 🔐 **Auth** | Login, Register, Password Recovery via email |
| 🎵 **Media** | Upload / stream / download MP3 + lyrics (TXT) |
| 👤 **Profiles** | User profiles, role system (admin / premium / user) |
| 🛡️ **Admin Panel** | Ban users, view security logs, force-unblock rate limits |
| 📧 **Mail** | PHPMailer + MailHog (zero config in dev) |
| 🐳 **Docker** | One-command spin-up, no local dependencies needed |

---

## 🔒 Security Architecture

> Full breakdown → [`SECURITY.md`](SECURITY.md) · [📄 PDF](docs/SECURITY.pdf)

<details>
<summary><strong>Click to expand — 12 security layers implemented</strong></summary>

| Layer | Implementation |
|-------|---------------|
| **Password Hashing** | Argon2ID via `password_hash()` (OWASP recommended) |
| **Session Security** | HttpOnly · SameSite=Lax · Secure · strict_mode · 30min timeout |
| **Session Fixation** | `session_regenerate_id(true)` on every login |
| **IP Binding** | Session invalidated on IP change (anti-hijacking) |
| **CSRF Protection** | Per-form signed tokens, validated server-side |
| **Rate Limiting** | DB-backed, atomic `INSERT ON DUPLICATE KEY UPDATE`, per-user + per-IP |
| **SQL Injection** | 100% PDO prepared statements, `strict_types=1` everywhere |
| **XSS Prevention** | Centralized `e()` output-escape function, CSP headers |
| **File Upload** | MIME + extension whitelist, SHA-256 integrity check on download |
| **Path Traversal** | `realpath()` jail + `basename()` sanitization |
| **HTTP Headers** | HSTS · X-Frame-Options · X-Content-Type-Options · Referrer-Policy |
| **Security Logging** | Dual-channel: rotating file + DB (WARNING/CRITICAL only) |

</details>

---

## 🚀 Quick Start

### Prerequisites
- [Docker](https://www.docker.com/) + Docker Compose

### 1 — Clone & configure
```bash
git clone https://github.com/your-username/MusicProject.git
cd MusicProject
cp .env.example .env       # edit with your values
```

### 2 — Launch
```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| 🌐 App | http://localhost |
| 📬 MailHog (email UI) | http://localhost:8025 |

### 3 — Done
The database schema is auto-imported from `database/migrations/database.sql` on first boot.

---

## 📁 Project Structure

```
├── public/            ← HTTP entry points (Apache document root)
│   └── assets/        ← CSS · JS · fonts
├── includes/          ← Shared logic (no direct HTTP access)
│   ├── authentication.php   ← Session · CSRF · headers
│   ├── RateLimiter.php      ← Brute-force protection
│   └── SecurityLogger.php   ← Dual-channel audit log
├── storage/
│   ├── logs/          ← Rotating security logs
│   └── uploads/       ← Audio & lyrics (outside document root)
├── database/
│   └── migrations/    ← Auto-imported SQL schema
├── docs/              ← Screenshots & demo assets
├── .env.example       ← Environment template
├── docker-compose.yml
└── Dockerfile
```

---

## 🧪 Test Accounts *(after first boot)*

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | set during migration |
| User | register via `/register.php` | — |

---

## 📖 Tech Stack

- **Backend** — PHP 8.2, PDO/MySQL
- **Frontend** — Vanilla JS, CSS3 (no frameworks)
- **Database** — MySQL 8.0
- **Mail** — PHPMailer 7 + MailHog (dev)
- **Server** — Apache 2.4 (mod_rewrite + mod_headers)
- **Container** — Docker + Docker Compose

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first.  
Please read [`SECURITY.md`](SECURITY.md) before contributing to security-sensitive areas.

---

<div align="center">
Made with ♥ and a lot of <code>declare(strict_types=1)</code>
</div>
