# auth_module  
**A secure, reusable authentication backend template that I will be using for my future projects**

`auth_module` is a production-ready authentication foundation built with **Node.js, Express, and PostgreSQL**.  
It is designed to be **copied, reused, and extended** across future projects with minimal setup.

This repository prioritizes:
- security-by-default
- testability
- clean separation of concerns
- real-world attack awareness (logging + throttling)

---

## Features

### Authentication
- Local email + password signup/login
- Secure password hashing (Argon2)
- Cookie-based sessions stored in PostgreSQL
- Sliding session expiration (e.g., 24 hours)
- `/auth/me` session validation
- Logout with session invalidation

### Security
- Parameterized SQL queries (SQL injection safe)
- Suspicious input detection (e.g. `OR '1'='1' --`)
- Logs **only suspicious excerpts**, never normal values
- Never logs:
  - passwords
  - tokens
  - session IDs
  - cookies
- Rate-limited suspicious logging per IP
- Persistent IP offender tracking (JSON)
- Hardened HTTP headers via `helmet`

### Testing
- Full Jest + Supertest coverage
- DB-backed integration tests
- Security behavior tests:
  - SQL injection detection
  - secret-safe logging
  - IP-based rate limiting
- Test-safe async handling (no hanging handles)

---

## Tech Stack

- Node.js
- Express (CommonJS)
- PostgreSQL
- `pg` connection pool
- Argon2
- Jest + Supertest
- Helmet, CORS, Cookie Parser
- Zod (request validation)
- Pino (structured logging)

---

## Project Structure
```tree
auth_module/
├─ src/
│ ├─ app.js # Express app (no listen)
│ ├─ server.js # Server entry point
│ ├─ db.js # Postgres pool (dev/test aware)
│ └─ security/
│ ├─ suspiciousFileLogger.js
│ └─ ipThrottleStore.js
├─ routes/
│ └─ auth.js
├─ middleware/
│ ├─ requireAuth.js
│ ├─ suspiciousInputLogger.js
│ ├─ notFound.js
│ └─ errorHandler.js
├─ sql/
│ └─ schema.sql
├─ tests/
│ ├─ auth.local.test.js
│ ├─ health.test.js
│ └─ helpers/
│ └─ dbReset.js
├─ log/
│ ├─ sql.inject.test.js
│ ├─ no-secrets-logged.test.js
│ └─ rate-limit-logging.test.js
├─ .env.example
├─ .gitignore
├─ package.json
└─ README.md
```
> Runtime logs are written to `log/` but ignored by Git.  
> Only test files inside `log/` are committed.

---

## Setup

### 1. Install dependencies

```bash
npm install
```
---

### 2. Environment variables

Create .env in the project root:
```
NODE_ENV=development
PORT=4000
FRONTEND_ORIGIN=http://localhost:3000

PGHOST=localhost
PGPORT=5432
PGUSER=auth_user
PGPASSWORD=your_password
PGDATABASE=auth_module
PGTESTDATABASE=auth_module_test

SUSPICIOUS_LOG_PATH=log/suspiciousInput.txt
SUSPICIOUS_IPS_PATH=log/suspiciousIps.json
```
---

### 3. PostgreSQL setup
```psql
CREATE DATABASE auth_module;
CREATE DATABASE auth_module_test;

CREATE USER auth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_module TO auth_user;
GRANT ALL PRIVILEGES ON DATABASE auth_module_test TO auth_user;

Apply schema to both databases:
psql -h localhost -U auth_user -d auth_module -f sql/schema.sql
psql -h localhost -U auth_user -d auth_module_test -f sql/schema.sql
```
---

### 4. Running the Service
Development (auto-reload)
```bash
npm run dev
```
Production-style run
```bash
npm start
```
Health checks

- GET /health
- GET /health/db

---

Auth API Endpoints

---
Signup

POST /auth/signup
```json
{ "email": "user@example.com", "password": "StrongPassword123!" }
```
---
Login

POST /auth/login
```json
{ "email": "user@example.com", "password": "StrongPassword123!" }
```
---
Current User

- GET /auth/me

Logout

- POST /auth/logout
---

Session Design

- Cookie name: sid
- HttpOnly cookie (JS cannot read it)
- Session rows stored in PostgreSQL
- Sliding expiration extends on activity
- Sessions can be revoked server-side

Why cookies instead of JWTs?

- No localStorage XSS risk
- Centralized session revocation
- Cleaner fit for web apps (Next.js / React)

---

Suspicious Input Detection

- The system detects SQL injection-style patterns across:
- query parameters
- request body
- route parameters
- Logging rules
- Logs only when suspicious patterns appear
- Logs only the suspicious excerpt
- Never logs sensitive fields
- Normal input is never logged

Files

- log/suspiciousInput.txt → JSONL suspicious events
- log/suspiciousIps.json → per-IP tracking and rate limits

---

Rate-Limiting Security Logs

To prevent log flooding:

- Suspicious payload logging is rate-limited per IP
- Default: 5 logs per minute per IP
- Excess attempts are tracked but not logged repeatedly
- IP metadata is persisted for inspection

---

### Testing

Run tests once:
npm test
npm run test:watch

Coverage includes:

- API correctness
- DB integration
- session handling
- SQL injection detection
- secret-safe logging
- IP throttling behavior

## Using This Repo as a Template

### Option 1: GitHub Template (recommended)

- Mark repo as Template Repository
- Create new services with one click

### Option 2: Manual reuse

- Copy repo folder
- Rename service references
- Update .env.example
- Create new databases
- Apply schema
- Start building features

This repo is intentionally structured to be reused as-is.

---

### Production Checklist

Before deploying:

- NODE_ENV=production
- secure cookie flags
- HTTPS enforced
- correct FRONTEND_ORIGIN
- log rotation strategy
- external rate limiting (Redis) if multi-instance
- CSRF protection strategy for cookies

---

### Roadmap

- Frontend integration
- Google OAuth (OIDC)
- Email verification + password reset
- CSRF hardening
- Redis-backed session store (optional)

