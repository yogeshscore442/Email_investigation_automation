# Phase 7: PhishScope SOC Production Security Hardening — Architecture & Security Audit

**Assessment Date**: 2026-11-06  
**Auditor**: Senior Application Security Engineer & SOC Lead Architect  
**Classification**: TLP:AMBER | Internal SOC Security Review  
**Project**: AI-Powered Automated Email Investigation & SOC Incident Correlation Platform (PhishScope SOC)  
**Scope**: Full-stack audit across Flask REST API, React 18 SPA, SQLite database, Splunk SIEM integration, Threat Intelligence integrations, and authentication subsystems before production hardening.

---

## 1. Executive Summary

Prior to applying Phase 7 production security hardening, a comprehensive source code and architectural security inspection was conducted across all backend modules, routes, configuration files, and frontend API clients. 

While Phases 1 through 6D established robust forensic parsing, static macro inspection, HTML sanitization via `bleach`, local-only attachment hashing, and defense against prompt injection, several architectural weaknesses were identified that must be addressed for enterprise production deployment.

### Audit Summary Matrix

| Domain | Status Before Hardening | Severity | Primary Risk |
| :--- | :--- | :--- | :--- |
| **1. Authentication & Sessions** | Static API Keys Only; No User DB; Auth Disabled by Default | **HIGH** | Lack of individual analyst accounts, password hashing, and session expiration. |
| **2. Role-Based Access Control** | Static Role Header (`X-User-Role`) | **MEDIUM** | Weak client-side role assertion if API auth is disabled or bypassed. |
| **3. API Rate Limiting** | Flask-Limiter on Select Endpoints | **LOW** | General API endpoints lack global brute-force and login throttling. |
| **4. CORS Configuration** | Wildcard `origins: "*"` | **MEDIUM** | In production, permits cross-origin requests from arbitrary origins. |
| **5. HTTP Security Headers** | Missing Security Headers | **MEDIUM** | Missing CSP, HSTS, X-Content-Type-Options, and X-Frame-Options. |
| **6. SSRF Protection** | Partial (Heuristic/Static Only) | **HIGH** | URL enrichment / RDAP requests could target internal IPs or cloud metadata (169.254.169.254). |
| **7. Splunk TLS Verification** | Default `verify=False` | **MEDIUM** | Insecure TLS validation in lab environment; lacks custom CA bundle support. |
| **8. Database Security** | SQLite File Without WAL / Automated Hot Backups | **LOW** | Database concurrency and lack of point-in-time disaster recovery scripts. |
| **9. Secrets & Git Hygiene** | Excluded from Git (`.gitignore` verified) | **INFORMATIONAL** | `.env.example` lacks Splunk and JWT variables; credentials safe from Git history. |
| **10. Container Deployment** | No Docker Configuration | **LOW** | Missing isolated, unprivileged containerization for production deployment. |

---

## 2. In-Depth Architectural Findings

### 2.1 Authentication and Session Management
- **Existing Logic**: `backend/app/utils/auth.py` evaluates `Config.API_AUTH_ENABLED` (defaults to `false` in development). Authentication relies on two static shared strings (`Config.API_KEY` and `Config.ADMIN_API_KEY`).
- **Defects & Weaknesses**:
  1. No persistent `User` model exists in the database.
  2. Individual analysts cannot authenticate with unique credentials or undergo password rotation.
  3. No password hashing algorithm (`pbkdf2:sha256` or `scrypt`) is in use for analyst identities.
  4. No signed session tokens (JWT or secure tokens) with standard claims (`exp`, `iat`, `sub`, `role`) exist.
  5. No analyst login rate limiting or failed login lockout mechanism exists.
  6. Authorization currently accepts an unauthenticated `X-User-Role` header when `API_AUTH_ENABLED=False`.

### 2.2 Network & CORS Boundaries
- **Existing Logic**: `backend/app/__init__.py` initializes CORS with:
  ```python
  CORS(app, resources={r"/api/*": {"origins": "*"}})
  ```
- **Defects & Weaknesses**:
  1. Wildcard `*` allows cross-origin scripts from any unauthorized web domain to query API endpoints if credentials or sessions are enabled.
  2. Should be restricted to explicit allowed origins via configurable `CORS_ORIGINS` (e.g., `http://127.0.0.1:5173`, `http://localhost:5173`).

### 2.3 HTTP Response Headers & Defense-in-Depth
- **Existing Logic**: Flask handles requests without an `@app.after_request` security header hook.
- **Defects & Weaknesses**:
  1. Missing `Content-Security-Policy` (CSP) header.
  2. Missing `X-Content-Type-Options: nosniff` (vulnerable to MIME sniffing).
  3. Missing `X-Frame-Options: DENY` (vulnerable to clickjacking if rendered in iframes).
  4. Missing `Strict-Transport-Security` (HSTS) header for TLS enforcement.
  5. Missing `Referrer-Policy: strict-origin-when-cross-origin`.
  6. Missing `Permissions-Policy`.

### 2.4 Server-Side Request Forgery (SSRF)
- **Existing Logic**: `UrlAnalyzerModule` and `ThreatIntelClient` inspect URLs and domains.
- **Defects & Weaknesses**:
  1. While attachment hashing is strictly passive (zero uploads), external URL lookups or future URL crawler features could be tricked into querying private subnets (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.0.0/16`), or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`).
  2. Strict IP validation and SSRF sanitization must be enforced on any external fetch, rejecting non-public destinations.

### 2.5 Splunk Enterprise TLS Configuration
- **Existing Logic**: `SplunkClient` initializes with `self.verify_ssl = Config.SPLUNK_SSL_VERIFY` (default `false`) and calls `urllib3.disable_warnings(InsecureRequestWarning)`.
- **Defects & Weaknesses**:
  1. Disabling TLS verification leaves communications vulnerable to adversary-in-the-middle (AITM) attacks on enterprise networks.
  2. Production configurations require support for either custom CA bundles (`SPLUNK_CA_BUNDLE` or cert file path) or strict TLS verification (`verify=True`).

### 2.6 SQLite Database Architecture & Recovery
- **Existing Logic**: Database initialized via SQLAlchemy with `sqlite:///{BASE_DIR / 'email_investigation.db'}`.
- **Defects & Weaknesses**:
  1. SQLite defaults to DELETE journal mode rather than Write-Ahead Logging (`WAL`), limiting multi-process concurrency between web workers.
  2. No automated backup or snapshot utility exists for disaster recovery or forensic evidence archival.

### 2.7 Secrets and Configuration Hygiene
- **Existing Logic**: Secrets stored in `backend/.env`.
- **Strengths**:
  1. Git status and commit history show `.env` has never been committed.
  2. `.gitignore` comprehensively excludes `.env`, `.env.*`, and `*.db`.
- **Weaknesses**:
  1. `backend/.env.example` lacks placeholders for `SPLUNK_*` variables, `JWT_SECRET_KEY`, and `CORS_ORIGINS`.

---

## 3. Remediation Roadmap for Phase 7

1. **Authentication & Authorization**:
   - Create `User` model with secure password hashing (`generate_password_hash`, `check_password_hash`).
   - Implement JWT-based analyst session tokens with expiration and role claims (`analyst`, `lead`, `admin`).
   - Provide `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, `/api/auth/refresh`, and `/api/auth/users` endpoints.
   - Implement brute-force protection and rate limiting on `/api/auth/login`.
   - Maintain 100% backward compatibility with existing API key and testing fixtures.

2. **Backend Security & Middleware**:
   - Add security response headers middleware (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `HSTS`, `Referrer-Policy`).
   - Configure restrictive CORS origins.
   - Enforce global JSON error formatting without leaking stack traces.
   - Build SSRF protection utility (`validate_ssrf_safe_url`, `is_private_or_reserved_ip`).

3. **Splunk & Database Security**:
   - Add CA bundle path support to `SplunkClient` and `Config.SPLUNK_SSL_VERIFY`.
   - Enable SQLite `WAL` mode and write hot backup script `backend/scripts/backup_db.py`.

4. **Production Deployment Assets**:
   - Create backend `Dockerfile` (Python 3.10 slim, non-root user).
   - Create frontend `Dockerfile` (multi-stage Vite build + Nginx alpine).
   - Create `docker-compose.yml` with health checks, volume isolation, and production networking.
   - Update `.env.example` and write deployment guide.

5. **Verification & Testing**:
   - Develop comprehensive `backend/tests/test_phase7_security_hardening.py` testing auth bypass, RBAC, SQL injection, SSRF, path traversal, rate limiting, and CORS.
   - Verify all 131 existing regression tests continue to pass.

