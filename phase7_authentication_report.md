# Phase 7: PhishScope SOC — Authentication & Authorization Hardening Report

**Assessment Date**: 2026-11-06  
**Auditor**: Senior Application Security Engineer & SOC Lead Architect  
**Classification**: TLP:AMBER | Internal SOC Security Review  
**Project**: AI-Powered Automated Email Investigation & SOC Incident Correlation Platform (PhishScope SOC)  
**Status**: **VERIFIED**

---

## 1. Executive Summary

Phase 7 introduces enterprise-grade identity and access control to the PhishScope SOC platform. Prior to this phase, authentication relied exclusively on static shared API keys and client-asserted role headers. 

The hardened architecture introduces:
1. **Database-Backed User Accounts**: Dedicated `users` table storing individual analyst identities.
2. **Cryptographically Strong Password Hashing**: PBKDF2 with SHA-256 and 600,000 hash iterations (`pbkdf2:sha256:600000`).
3. **Signed JWT Session Tokens**: Cryptographically signed access tokens using HS256 with explicit expiration (`exp`), subject (`sub`), role, and issue time (`iat`).
4. **Strict Role-Based Access Control (RBAC)**: A 4-tier hierarchical permission model (`admin` > `lead` > `analyst` > `auditor`).
5. **Brute-Force & Lockout Safeguards**: Account lockout after 5 consecutive failed login attempts for 15 minutes, coupled with endpoint rate limiting (10 requests/minute).
6. **Zero Password Leakage**: Passwords and password hashes are strictly omitted from all serialization methods, responses, and log messages.

---

## 2. Authentication Architecture

### 2.1 User Data Model (`backend/app/models/user.py`)

```python
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
```

- **Password Storage**: Uses Werkzeug's `generate_password_hash(password, method='pbkdf2:sha256:600000')` to protect against offline GPU/ASIC rainbow table attacks.
- **Verification**: Evaluated with `check_password_hash` in constant time to eliminate timing side-channels.
- **Enumeration Protection**: For non-existent usernames, a dummy hash evaluation is performed to normalize response timing.

### 2.2 JWT Session Tokens (`backend/app/utils/auth.py`)

- **Signature**: HMAC-SHA256 using `Config.JWT_SECRET_KEY`.
- **Token Claims**:
  ```json
  {
    "sub": "1",
    "username": "lead_analyst",
    "email": "lead@soc.local",
    "role": "lead",
    "iat": 1794052800,
    "exp": 1794081600
  }
  ```
- **Lifecycle**: Default lifespan of 8 hours (`Config.JWT_EXPIRATION_HOURS = 8`). Refresh endpoint (`POST /api/auth/refresh`) allows session extension for active, unlocked accounts.

---

## 3. Role-Based Access Control (RBAC) Matrix

The platform enforces a strict hierarchical integer permission level:

$$\text{admin (4)} > \text{lead (3)} > \text{analyst (2)} > \text{auditor (1)}$$

| API Endpoint | HTTP Method | Minimum Required Role | Description & Privilege Enforcement |
| :--- | :---: | :---: | :--- |
| `/api/auth/login` | `POST` | *Public* | Authenticates credentials, returns signed JWT. |
| `/api/auth/me` | `GET` | `auditor` (1) | Returns profile of current authenticated session. |
| `/api/auth/refresh` | `POST` | `auditor` (1) | Extends session token for active accounts. |
| `/api/dashboard/stats` | `GET` | `auditor` (1) | Read-only metrics, active campaigns, and provider health. |
| `/api/investigations` | `GET` | `auditor` (1) | Read-only investigation list view. |
| `/api/investigate/<id>` | `GET` | `auditor` (1) | Read-only forensic report view. |
| `/api/investigate/upload` | `POST` | `analyst` (2) | Uploads and parses `.eml` or `.msg` evidence files. |
| `/api/investigate/headers` | `POST` | `analyst` (2) | Submits raw headers for transit and SPF/DKIM/DMARC analysis. |
| `/api/incidents/correlate` | `POST` | `analyst` (2) | Triggers cross-investigation SIEM IOC clustering. |
| `/api/phase5/run/<id>` | `POST` | `analyst` (2) | Runs controlled attack simulations against Splunk. |
| `/api/incidents/<id>/actions/<id>/approve` | `POST` | `lead` (3) | Authorizes disruptive containment playbook action. |
| `/api/incidents/<id>/actions/<id>/execute` | `POST` | `admin` (4) | Executes destructive or endpoint-isolating containment action. |
| `/api/investigate/<id>` | `DELETE` | `admin` (4) | Permanently deletes investigation and disk artifacts. |
| `/api/auth/users` | `GET` | `admin` (4) | Lists all provisioned SOC analyst accounts. |
| `/api/auth/users` | `POST` | `admin` (4) | Provisions new analyst account with designated role. |

---

## 4. Brute-Force & Account Lockout Safeguards

- **Rate Limiting**: `/api/auth/login` is governed by Flask-Limiter (`10 per minute` per client IP).
- **Lockout Policy**:
  - `failed_login_attempts` tracks consecutive failed attempts.
  - Upon 5 consecutive failed authentications (`MAX_FAILED_LOGINS = 5`), the account is locked for 15 minutes (`ACCOUNT_LOCKOUT_MINUTES = 15`).
  - Subsequent requests return HTTP 423 Locked with the remaining lockout duration.
  - A successful authentication resets `failed_login_attempts` to 0 and clears `locked_until`.

---

## 5. Verification Results

| Test Case | Verification Target | Observed Behavior | Status |
| :--- | :--- | :--- | :---: |
| **AUTH-01** | Unauthenticated Access | HTTP 401 Unauthorized returned when `ENABLE_AUTH=true` without token. | **VERIFIED** |
| **AUTH-02** | Invalid Password | HTTP 401 returned; failed attempt counter incremented. | **VERIFIED** |
| **AUTH-03** | Account Lockout | HTTP 423 Locked returned after 5 failed attempts; locked for 15 min. | **VERIFIED** |
| **AUTH-04** | Valid Login | Returns HTTP 200, JWT token, user object (no password hash). | **VERIFIED** |
| **AUTH-05** | Role Hierarchy Enforcement | `analyst` cannot delete investigation (HTTP 403); `admin` can delete. | **VERIFIED** |
| **AUTH-06** | Playbook Authorization | Destructive execution strictly restricted to `admin` role. | **VERIFIED** |
| **AUTH-07** | Backward Compatibility | Static `API_KEY` and `ADMIN_API_KEY` continue to function seamlessly. | **VERIFIED** |

