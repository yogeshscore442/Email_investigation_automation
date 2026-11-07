import io
import time
from datetime import datetime, timedelta
import jwt
import pytest
from app import create_app
from app.config import Config
from app.models import db, User, Investigation
from app.utils.auth import SecurityAuth
from app.utils.network_security import is_ssrf_safe_url, is_ssrf_safe_ip
from app.utils.threat_intel import threat_intel

@pytest.fixture
def hardened_client():
    """Provides a test client with fresh database context for security testing."""
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENABLE_RATE_LIMITING"] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Ensure test users exist
            if not User.query.filter_by(username="sec_admin").first():
                admin = User(username="sec_admin", email="sec_admin@soc.local", role="admin")
                admin.set_password("AdminSecurePass2026!")
                db.session.add(admin)

            if not User.query.filter_by(username="sec_analyst").first():
                analyst = User(username="sec_analyst", email="sec_analyst@soc.local", role="analyst")
                analyst.set_password("AnalystSecurePass2026!")
                db.session.add(analyst)

            if not User.query.filter_by(username="sec_lead").first():
                lead = User(username="sec_lead", email="sec_lead@soc.local", role="lead")
                lead.set_password("LeadSecurePass2026!")
                db.session.add(lead)

            db.session.commit()
            yield client

class TestPhase7SecurityHardening:
    """Comprehensive test suite for Phase 7 Production Security Hardening."""

    def test_01_auth_bypass_prevention(self, hardened_client):
        """Verify unauthenticated requests and forged JWTs are strictly rejected."""
        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True

            # 1. Missing Authorization header
            res_unauth = hardened_client.get("/api/investigations")
            assert res_unauth.status_code == 401
            assert "Unauthorized" in res_unauth.get_json()["error"]

            # 2. Malformed token
            res_malformed = hardened_client.get(
                "/api/investigations",
                headers={"Authorization": "Bearer not-a-valid-token"}
            )
            assert res_malformed.status_code == 401

            # 3. Forged JWT signed with wrong secret key
            forged_payload = {
                "sub": "999",
                "username": "attacker",
                "role": "admin",
                "exp": datetime.utcnow() + timedelta(hours=1)
            }
            forged_jwt = jwt.encode(forged_payload, "completely-wrong-secret-key", algorithm="HS256")
            res_forged = hardened_client.get(
                "/api/investigations",
                headers={"Authorization": f"Bearer {forged_jwt}"}
            )
            assert res_forged.status_code == 401
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_02_broken_access_control_and_rbac(self, hardened_client):
        """Verify strict privilege boundary enforcement across Admin, Lead, and Analyst roles."""
        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True

            analyst = User.query.filter_by(username="sec_analyst").first()
            analyst_token = SecurityAuth.create_access_token(analyst)

            admin = User.query.filter_by(username="sec_admin").first()
            admin_token = SecurityAuth.create_access_token(admin)

            # Analyst can perform read actions
            res_read = hardened_client.get(
                "/api/investigations",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert res_read.status_code == 200

            # Analyst cannot delete an investigation (Admin required)
            res_del_analyst = hardened_client.delete(
                "/api/investigate/non-existent-id",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert res_del_analyst.status_code == 403
            assert "Forbidden" in res_del_analyst.get_json()["error"]

            # Analyst cannot list users (Admin required)
            res_users_analyst = hardened_client.get(
                "/api/auth/users",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert res_users_analyst.status_code == 403

            # Admin CAN access user management
            res_users_admin = hardened_client.get(
                "/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert res_users_admin.status_code == 200
            assert "users" in res_users_admin.get_json()
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_03_sql_injection_resilience(self, hardened_client):
        """Verify that SQL injection payloads do not cause database syntax exceptions or leakage."""
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT username, password_hash, 1, 1, 1, 1, 1, 1 FROM users --",
            "' AND 1=cast((SELECT password_hash FROM users LIMIT 1) as int) --",
        ]

        for payload in sqli_payloads:
            # Query endpoint with SQLi in parameter
            res = hardened_client.get(f"/api/investigations?query={payload}")
            assert res.status_code in [200, 400, 404]
            # Must not leak SQL syntax or error
            text_body = res.get_data(as_text=True).lower()
            assert "syntax error" not in text_body
            assert "sqlite3.operationalerror" not in text_body

            # Direct lookup endpoint with SQLi in route parameter
            res_route = hardened_client.get(f"/api/investigate/{payload}")
            assert res_route.status_code in [400, 404]
            assert "sqlite3.operationalerror" not in res_route.get_data(as_text=True).lower()

    def test_04_path_traversal_prevention(self, hardened_client):
        """Verify path traversal sequences in filenames and URLs are safely neutralized."""
        fake_eml = b"From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Safe\r\n\r\nSafe body"
        traversal_filenames = [
            "../../../../etc/passwd",
            "..\\..\\..\\Windows\\System32\\calc.exe",
            "....//....//....//boot.ini",
            "/var/log/syslog.eml"
        ]

        for tf in traversal_filenames:
            res = hardened_client.post(
                "/api/investigate/upload",
                data={"file": (io.BytesIO(fake_eml), tf)},
                content_type="multipart/form-data"
            )
            assert res.status_code in [201, 200, 400]
            if res.status_code in [200, 201]:
                data = res.get_json()
                # Ensure stored file does NOT escape storage directory
                evidence_path = data.get("evidence_path", "")
                if evidence_path:
                    assert ".." not in evidence_path

    def test_05_malicious_upload_handling(self, hardened_client):
        """Verify direct binaries and corrupted files are rejected prior to execution."""
        # 1. DOS/Windows Executable PE (MZ Header)
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
        res_pe = hardened_client.post(
            "/api/investigate/upload",
            data={"file": (io.BytesIO(pe_bytes), "invoice.eml")},
            content_type="multipart/form-data"
        )
        assert res_pe.status_code == 400
        assert "Executable binary detected" in res_pe.get_json()["error"]

        # 2. Linux Executable Binary (ELF Header)
        elf_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        res_elf = hardened_client.post(
            "/api/investigate/upload",
            data={"file": (io.BytesIO(elf_bytes), "document.eml")},
            content_type="multipart/form-data"
        )
        assert res_elf.status_code == 400
        assert "Executable binary detected" in res_elf.get_json()["error"]

        # 3. Empty 0-byte file
        res_empty = hardened_client.post(
            "/api/investigate/upload",
            data={"file": (io.BytesIO(b""), "empty.eml")},
            content_type="multipart/form-data"
        )
        assert res_empty.status_code == 400
        assert "Uploaded file is empty" in res_empty.get_json()["error"]

    def test_06_ssrf_protection(self):
        """Verify strict blocking of private subnets, loopback, and cloud metadata targets."""
        # Loopback
        assert is_ssrf_safe_ip("127.0.0.1") is False
        assert is_ssrf_safe_ip("::1") is False
        assert is_ssrf_safe_url("http://127.0.0.1:8089/services")[0] is False
        assert is_ssrf_safe_url("http://localhost:5000/")[0] is False

        # Cloud metadata services
        assert is_ssrf_safe_ip("169.254.169.254") is False
        assert is_ssrf_safe_url("http://169.254.169.254/latest/meta-data/")[0] is False
        assert is_ssrf_safe_url("http://metadata.google.internal/computeMetadata/v1/")[0] is False

        # Private RFC 1918
        assert is_ssrf_safe_ip("10.0.0.5") is False
        assert is_ssrf_safe_ip("172.16.50.1") is False
        assert is_ssrf_safe_ip("192.168.1.1") is False
        assert is_ssrf_safe_url("http://192.168.1.1/admin")[0] is False

        # Public internet address
        assert is_ssrf_safe_ip("8.8.8.8") is True
        assert is_ssrf_safe_ip("1.1.1.1") is True

        # Threat intel SSRF interception
        res_scan = threat_intel.submit_urlscan("http://169.254.169.254/secret")
        assert res_scan["status"] == "rejected"
        assert res_scan["verdict"] == "blocked"

        res_rdap = threat_intel.lookup_rdap_ip("127.0.0.1")
        assert res_rdap["status"] == "rejected"

    def test_07_secret_leakage_prevention(self, hardened_client):
        """Verify that sensitive API keys and password hashes are never exposed in responses."""
        endpoints_to_test = [
            "/api/health",
            "/api/dashboard/stats",
            "/api/siem/status",
            "/api/auth/me"
        ]

        sensitive_strings = [
            Config.SECRET_KEY,
            Config.JWT_SECRET_KEY,
            "pbkdf2:sha256",
        ]
        if Config.VIRUSTOTAL_API_KEY:
            sensitive_strings.append(Config.VIRUSTOTAL_API_KEY)
        if Config.ABUSEIPDB_API_KEY:
            sensitive_strings.append(Config.ABUSEIPDB_API_KEY)
        if Config.OPENAI_API_KEY:
            sensitive_strings.append(Config.OPENAI_API_KEY)

        for ep in endpoints_to_test:
            res = hardened_client.get(ep)
            body = res.get_data(as_text=True)
            for secret in sensitive_strings:
                if secret and len(secret) > 8:
                    assert secret not in body, f"Secret leaked in endpoint: {ep}"

    def test_08_cors_and_security_headers(self, hardened_client):
        """Verify that HTTP response headers contain robust browser security protections."""
        res = hardened_client.get("/api/health")
        assert res.status_code == 200

        # Check required security headers
        headers = res.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in headers
        assert "default-src 'self'" in headers["Content-Security-Policy"]

        # CORS Origin Check
        cors_res = hardened_client.get("/api/health", headers={"Origin": "http://127.0.0.1:5173"})
        assert cors_res.headers.get("Access-Control-Allow-Origin") in [
            "http://127.0.0.1:5173",
            "*"
        ]

    def test_09_login_rate_limiting_and_lockout(self, hardened_client):
        """Verify brute force lockout after 5 consecutive failed authentications."""
        analyst = User.query.filter_by(username="sec_analyst").first()
        analyst.failed_login_attempts = 0
        analyst.locked_until = None
        db.session.commit()

        # 5 consecutive failed login attempts
        for attempt in range(Config.MAX_FAILED_LOGINS):
            res = hardened_client.post(
                "/api/auth/login",
                json={"username": "sec_analyst", "password": "WrongPassword123!"}
            )
            assert res.status_code == 401

        # 6th attempt should be locked out (HTTP 423)
        res_locked = hardened_client.post(
            "/api/auth/login",
            json={"username": "sec_analyst", "password": "AnalystSecurePass2026!"}
        )
        assert res_locked.status_code == 423
        assert "locked" in res_locked.get_json()["error"].lower()

        # Clean up: unlock analyst account
        analyst.failed_login_attempts = 0
        analyst.locked_until = None
        db.session.commit()

    def test_10_session_security_and_jwt_lifecycle(self, hardened_client):
        """Verify complete JWT token issuance, verification, refresh, and logout lifecycle."""
        # 1. Successful Login
        login_res = hardened_client.post(
            "/api/auth/login",
            json={"username": "sec_analyst", "password": "AnalystSecurePass2026!"}
        )
        assert login_res.status_code == 200
        data = login_res.get_json()
        token = data.get("token")
        assert token is not None
        assert data.get("token_type") == "Bearer"

        # 2. Decode claims
        claims = SecurityAuth.decode_access_token(token)
        assert claims is not None
        assert claims["username"] == "sec_analyst"
        assert claims["role"] == "analyst"

        # 3. Authenticated profile lookup
        me_res = hardened_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        user_info = me_res.get_json()["user"]
        assert user_info["username"] == "sec_analyst"
        assert "password" not in user_info
        assert "password_hash" not in user_info

        # 4. Token refresh
        refresh_res = hardened_client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {token}"})
        assert refresh_res.status_code == 200
        new_token = refresh_res.get_json().get("token")
        assert new_token is not None

        # 5. Logout
        logout_res = hardened_client.post("/api/auth/logout")
        assert logout_res.status_code == 200
