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