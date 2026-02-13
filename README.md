# GoNyva Secure REST API

A lightweight, secure REST API built with **Slim Framework 4** following **OWASP Top 10** security guidelines. Includes JWT authentication, email sending via Dreamhost SMTP, and interactive Swagger documentation. Designed to run on **Dreamhost shared hosting** with a **Docker Compose** environment for local development.

## Tech Stack

- **Framework**: [Slim 4](https://www.slimframework.com/) — lightweight PHP micro-framework
- **Auth**: JWT via [firebase/php-jwt](https://github.com/firebase/php-jwt)
- **Email**: SMTP via [PHPMailer](https://github.com/PHPMailer/PHPMailer) (Dreamhost `gonyva.co`)
- **Logging**: [Monolog](https://github.com/Seldaek/monolog)
- **DI Container**: [PHP-DI](https://php-di.org/)
- **Environment**: [phpdotenv](https://github.com/vlucas/phpdotenv)
- **Database**: MySQL 8.0 via PDO (prepared statements only)
- **Docs**: [Swagger UI](https://swagger.io/tools/swagger-ui/) with OpenAPI 3.0 spec
- **Dev Environment**: Docker Compose (PHP 8.3 + Apache + MySQL 8.0)

## OWASP Top 10 Security Features

| OWASP | Threat | Implementation |
|-------|--------|----------------|
| **A01** | Broken Access Control | JWT auth, role-based access (user/admin), resource ownership checks |
| **A02** | Cryptographic Failures | bcrypt password hashing (cost 12), auto-rehash, 32+ char JWT secrets |
| **A03** | Injection | PDO prepared statements with `EMULATE_PREPARES=false`, HTML sanitization |
| **A04** | Insecure Design | File-based rate limiting (60 req/min), input validation, password complexity |
| **A05** | Security Misconfiguration | Secure HTTP headers (CSP, HSTS, X-Frame-Options), `.htaccess` lockdown, error suppression in production |
| **A06** | Vulnerable Components | Minimal dependencies, all managed via Composer |
| **A07** | Auth Failures | Generic error messages, constant-time password comparison, token expiry |
| **A08** | Data Integrity | Input validation/sanitization, JSON encoding with XSS flags |
| **A09** | Logging & Monitoring | Monolog with rotating log files, security event tagging, sensitive data redaction |
| **A10** | SSRF | No outbound requests (except SMTP), strict input validation |

## Project Structure

```
├── public/
│   ├── index.php              # Entry point (document root)
│   ├── .htaccess              # Apache rewrite rules + security headers
│   └── docs/
│       ├── index.html         # Swagger UI documentation page
│       └── openapi.json       # OpenAPI 3.0 specification
├── app/
│   ├── bootstrap.php          # App configuration & DI container
│   ├── routes.php             # Route definitions
│   ├── middleware.php         # Global middleware registration
│   ├── Controllers/
│   │   ├── AuthController.php     # Register, login, refresh, me, logout
│   │   ├── UserController.php     # CRUD users (role-based access)
│   │   ├── EmailController.php    # Send email via Dreamhost SMTP
│   │   └── HealthController.php   # Health check + docs serving
│   ├── Middleware/
│   │   ├── JwtMiddleware.php          # JWT token validation
│   │   ├── CorsMiddleware.php         # CORS handling
│   │   ├── RateLimitMiddleware.php    # File-based rate limiting
│   │   └── SecurityHeadersMiddleware.php  # OWASP security headers
│   ├── Services/
│   │   └── JwtService.php        # JWT token generation & validation
│   └── Handlers/
│       └── ErrorHandler.php       # Safe error responses
├── database/
│   └── migration.sql          # Schema + admin seed
├── docker/
│   └── php/
│       └── Dockerfile         # PHP 8.3 + Apache image
├── storage/                   # Rate limit data (auto-created)
├── logs/                      # Application logs (auto-created)
├── docker-compose.yml         # Local dev environment
├── .env.example               # Environment template
├── .htaccess                  # Root htaccess (redirects to public/)
└── composer.json
```

---

## Local Development (Docker)

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Quick Start

```bash
# 1. Clone the repo
git clone <repo-url> gonyva-api
cd gonyva-api

# 2. Create environment file
cp .env.example .env
# Edit .env — set JWT_SECRET and SMTP credentials

# 3. Start the environment
docker compose up --build -d

# 4. Verify it's running
curl http://localhost:8080/health
```

This starts two containers:
- **gonyva-api** — PHP 8.3 + Apache on port `8080`
- **gonyva-db** — MySQL 8.0 on port `3306`

The database migration (`database/migration.sql`) runs automatically on first start and seeds an admin user.

### Default Admin Credentials

| Field | Value |
|-------|-------|
| Email | `admin@example.com` |
| Password | `Admin123!` |

> **Change the admin password immediately after first login.**

### Docker Commands

```bash
# Start
docker compose up -d

# Stop
docker compose down

# View logs
docker logs gonyva-api -f

# Reset database (wipe volume)
docker compose down -v && docker compose up --build -d

# Run without Docker (PHP built-in server, requires local MySQL)
composer start
```

### Local `.env` Configuration

Key settings for Docker development:

```env
APP_ENV=local
APP_DEBUG=true
DB_HOST=db
DB_NAME=gonyva_api
DB_USER=gonyva
DB_PASS=gonyva_secret
JWT_SECRET=<generate with: php -r "echo bin2hex(random_bytes(32));">
CORS_ALLOWED_ORIGINS=*
```

---

## API Documentation (Swagger)

Interactive API documentation is available at:

```
http://localhost:8080/docs
```

The Swagger UI provides:
- **Quick Start Guide** — step-by-step instructions to register, get a token, and make requests
- **Interactive API Explorer** — try all endpoints directly in the browser
- **Schema documentation** — request/response models with examples
- **Authorize button** — paste your JWT token to test protected endpoints

The raw OpenAPI 3.0 spec is available at:

```
http://localhost:8080/docs/openapi.json
```

---

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | Swagger UI documentation |
| `POST` | `/api/v1/auth/register` | Register new user |
| `POST` | `/api/v1/auth/login` | Login and receive JWT tokens |
| `POST` | `/api/v1/auth/refresh` | Refresh an expired access token |

### Protected Endpoints (requires `Authorization: Bearer <token>`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/auth/me` | Get current user profile |
| `POST` | `/api/v1/auth/logout` | Logout (discard token client-side) |
| `GET` | `/api/v1/users` | List all users *(admin only)* |
| `GET` | `/api/v1/users/{id}` | Get user by ID *(own profile or admin)* |
| `PUT` | `/api/v1/users/{id}` | Update user *(own profile or admin)* |
| `DELETE` | `/api/v1/users/{id}` | Soft-delete user *(admin only)* |
| `POST` | `/api/v1/email/send` | Send email via Dreamhost SMTP |

### Example Requests

**Register:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"SecurePass1"}'
```

**Login:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Admin123!"}'
```

**Get current user (authenticated):**
```bash
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Send email (authenticated):**
```bash
curl -X POST http://localhost:8080/api/v1/email/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "name": "Jane Doe",
    "email": "recipient@example.com",
    "message": "<p>Hello! This is a <strong>test email</strong> with HTML content.</p>"
  }'
```

### Email Endpoint Details

The `POST /api/v1/email/send` endpoint:

- **Requires**: JWT authentication
- **SMTP**: Sends via Dreamhost's `smtp.dreamhost.com` (port 587, STARTTLS)
- **HTML support**: The `message` field accepts HTML content which is sanitized before sending
- **Allowed HTML tags**: `<p>`, `<br>`, `<strong>`, `<b>`, `<em>`, `<i>`, `<u>`, `<h1>`–`<h6>`, `<ul>`, `<ol>`, `<li>`, `<a>`, `<img>`, `<blockquote>`, `<pre>`, `<code>`, `<hr>`, `<span>`, `<div>`, `<table>` and related tags
- **Stripped**: JavaScript event handlers (`onclick`, `onerror`, etc.) and `javascript:` URIs

| Status | Meaning |
|--------|---------|
| `200` | Email sent successfully |
| `401` | Missing or invalid JWT token |
| `422` | Validation error (invalid name/email/message) |
| `429` | Rate limit exceeded |
| `500` | SMTP or server error |

---

## Dreamhost Production Deployment

### 1. Upload Files

Upload the project to your Dreamhost server via SFTP or SSH (exclude `docker/`, `docker-compose.yml`, `.dockerignore`).

### 2. Install Dependencies

```bash
# Via SSH on Dreamhost
cd ~/yourdomain.com
composer install --no-dev --optimize-autoloader
```

If SSH is not available, upload the `vendor/` folder from your local machine.

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with production settings:

```env
APP_ENV=production
APP_DEBUG=false
APP_URL=https://api.gonyva.co

DB_HOST=mysql.gonyva.co
DB_NAME=your_database
DB_USER=your_db_user
DB_PASS=your_db_password

JWT_SECRET=<64+ character random string>

CORS_ALLOWED_ORIGINS=https://gonyva.co

SMTP_HOST=smtp.dreamhost.com
SMTP_PORT=587
SMTP_ENCRYPTION=tls
SMTP_USER=noreply@gonyva.co
SMTP_PASS=your_email_password
SMTP_FROM_EMAIL=noreply@gonyva.co
SMTP_FROM_NAME="GoNyva API"
```

### 4. Set Document Root

In Dreamhost panel → **Manage Domains** → **Edit**, set the web directory to:

```
yourdomain.com/public
```

### 5. Create Database

- Create a MySQL database and user in Dreamhost panel → **MySQL Databases**
- Import `database/migration.sql` via **phpMyAdmin**

### 6. Set Permissions

```bash
chmod 750 storage/ logs/
chmod 640 .env
```

### Directory Structure on Dreamhost

```
/home/username/yourdomain.com/
├── public/          ← Document root
│   └── docs/        ← Swagger UI
├── app/
├── vendor/
├── database/
├── storage/
├── logs/
├── .env
├── .htaccess
└── composer.json
```

---

## Security Headers

All API responses include these OWASP-recommended headers:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Cache-Control` | `no-store, no-cache, must-revalidate` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `X-RateLimit-Limit` | `60` |
| `X-RateLimit-Remaining` | *(decrements per request)* |
| `X-RateLimit-Reset` | *(unix timestamp)* |

---

## License

MIT
