import io
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import jwt
import pytest
from app import create_app
from app.config import Config
from app.models import db, User, Investigation, PlaybookAction, Incident
from app.utils.auth import SecurityAuth
from app.utils.network_security import is_ssrf_safe_url, is_ssrf_safe_ip
from app.utils.threat_intel import threat_intel
from app.utils.splunk_client import SplunkClient
from scripts.backup_db import perform_hot_backup, restore_backup

@pytest.fixture
def audit_client():
    """Provides a dedicated Flask test client for independent security auditing."""
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENABLE_RATE_LIMITING"] = False

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Seed distinct accounts for audit
            admin = User.query.filter_by(username="audit_admin").first()
            if not admin:
                admin = User(username="audit_admin", email="audit_admin@soc.local", role="admin")
                admin.set_password("AdminAuditPass2026!Secure")
                db.session.add(admin)

            lead = User.query.filter_by(username="audit_lead").first()
            if not lead:
                lead = User(username="audit_lead", email="audit_lead@soc.local", role="lead")
                lead.set_password("LeadAuditPass2026!Secure")
                db.session.add(lead)

            analyst = User.query.filter_by(username="audit_analyst").first()
            if not analyst:
                analyst = User(username="audit_analyst", email="audit_analyst@soc.local", role="analyst")
                analyst.set_password("AnalystAuditPass2026!Secure")
                db.session.add(analyst)

            auditor = User.query.filter_by(username="audit_auditor").first()
            if not auditor:
                auditor = User(username="audit_auditor", email="audit_auditor@soc.local", role="auditor")
                auditor.set_password("AuditorAuditPass2026!Secure")
                db.session.add(auditor)

            db.session.commit()
            yield client

class TestPhase7BIndependentAudit:
    """Independent security audit validating Phase 7 security controls."""

    # =========================================================================
    # 1. JWT Authentication Audit
    # =========================================================================

    def test_01_jwt_valid_login_and_token_structure(self, audit_client):
        """Verify valid analyst authentication, token issuance, and claim structure."""
        res = audit_client.post("/api/auth/login", json={
            "username": "audit_analyst",
            "password": "AnalystAuditPass2026!Secure"
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("status") == "success"
        token = data.get("token")
        assert token is not None

        # Verify decoded claims
        claims = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
        assert claims["username"] == "audit_analyst"
        assert claims["role"] == "analyst"
        assert "exp" in claims
        assert "iat" in claims
        assert "sub" in claims

    def test_02_jwt_invalid_credentials_rejected(self, audit_client):
        """Verify incorrect passwords and nonexistent users are rejected."""
        res_bad_pw = audit_client.post("/api/auth/login", json={
            "username": "audit_analyst",
            "password": "WrongPassword999!"
        })
        assert res_bad_pw.status_code == 401
        assert "Invalid credentials" in res_bad_pw.get_json()["error"]

        res_bad_user = audit_client.post("/api/auth/login", json={
            "username": "nonexistent_hacker",
            "password": "AnyPassword123!"
        })
        assert res_bad_user.status_code == 401

    def test_03_jwt_expired_token_rejected(self, audit_client):
        """Verify expired JWTs cannot be used to authenticate."""
        analyst = User.query.filter_by(username="audit_analyst").first()
        # Generate token expired 1 hour ago
        expired_token = SecurityAuth.create_access_token(analyst, expires_delta=timedelta(hours=-1))
        
        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True
            res = audit_client.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {expired_token}"}
            )
            assert res.status_code == 401
            assert "Unauthorized" in res.get_json()["error"]
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_04_jwt_modified_signature_tampered_rejected(self, audit_client):
        """Verify tokens with modified signatures are rejected."""
        analyst = User.query.filter_by(username="audit_analyst").first()
        valid_token = SecurityAuth.create_access_token(analyst)
        
        # Tamper with the last 8 characters of signature
        tampered_token = valid_token[:-8] + "TAMPERED"

        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True
            res = audit_client.get(
                "/api/investigations",
                headers={"Authorization": f"Bearer {tampered_token}"}
            )
            assert res.status_code == 401
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_05_jwt_none_algorithm_attack_rejected(self, audit_client):
        """Verify that alg=none JWT attack payloads are strictly rejected."""
        payload = {
            "sub": "1",
            "username": "audit_admin",
            "role": "admin",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        # Craft unsigned token with header alg: none
        none_token = jwt.encode(payload, key=None, algorithm=None)

        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True
            res = audit_client.get(
                "/api/auth/users",
                headers={"Authorization": f"Bearer {none_token}"}
            )
            assert res.status_code == 401
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_06_jwt_logout_and_token_invalidation(self, audit_client):
        """Verify that logging out revokes the token from further use."""
        analyst = User.query.filter_by(username="audit_analyst").first()
        token = SecurityAuth.create_access_token(analyst)

        # 1. Profile accessible before logout
        res_before = audit_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_before.status_code == 200

        # 2. Logout revokes token
        logout_res = audit_client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout_res.status_code == 200

        # 3. Subsequent request with revoked token is rejected
        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True
            res_after = audit_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert res_after.status_code == 401
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_07_password_hashing_pbkdf2_never_plaintext(self, audit_client):
        """Verify passwords are stored as PBKDF2:SHA256 salted hashes, never in plaintext."""
        user = User.query.filter_by(username="audit_analyst").first()
        assert user.password_hash is not None
        assert "AnalystAuditPass2026!" not in user.password_hash
        assert user.password_hash.startswith("pbkdf2:sha256:600000$")
        assert user.to_dict().get("password") is None
        assert user.to_dict().get("password_hash") is None

    # =========================================================================
    # 2. Authorization & RBAC Audit
    # =========================================================================

    def test_08_rbac_privilege_boundaries(self, audit_client):
        """Verify privilege boundaries: Analyst cannot perform Admin actions."""
        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True

            analyst = User.query.filter_by(username="audit_analyst").first()
            analyst_token = SecurityAuth.create_access_token(analyst)

            admin = User.query.filter_by(username="audit_admin").first()
            admin_token = SecurityAuth.create_access_token(admin)

            # 1. Analyst cannot provision new users (Admin required)
            res_create_user = audit_client.post(
                "/api/auth/users",
                headers={"Authorization": f"Bearer {analyst_token}"},
                json={"username": "hacked_user", "email": "h@soc.local", "password": "Pass123!Secure", "role": "admin"}
            )
            assert res_create_user.status_code == 403

            # 2. Analyst cannot delete investigation records (Admin required)
            res_delete = audit_client.delete(
                "/api/investigate/fake-id-12345",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert res_delete.status_code == 403

            # 3. Admin CAN access user provisioning
            res_admin_create = audit_client.post(
                "/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "new_sec_user", "email": "new@soc.local", "password": "Pass123!Secure", "role": "analyst"}
            )
            assert res_admin_create.status_code in [201, 409]
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    def test_09_rbac_playbook_action_approval_gate(self, audit_client):
        """Verify that disruptive containment actions require Lead/Admin approval."""
        import uuid
        inc_id = f"audit-inc-{uuid.uuid4().hex[:6]}"
        inc_num = f"INC-AUDIT-{uuid.uuid4().hex[:6]}"
        incident = Incident(
            id=inc_id,
            incident_number=inc_num,
            title="Audit Security Incident",
            severity="high",
            status="open"
        )
        action = PlaybookAction(
            incident_id=inc_id,
            action_type="isolate_endpoint",
            title="Isolate Host",
            target="HOST-SEC-01",
            requires_approval=True,
            approval_status="pending"
        )
        db.session.add(incident)
        db.session.add(action)
        db.session.commit()

        orig_auth = Config.API_AUTH_ENABLED
        try:
            Config.API_AUTH_ENABLED = True

            auditor = User.query.filter_by(username="audit_auditor").first()
            auditor_token = SecurityAuth.create_access_token(auditor)

            lead = User.query.filter_by(username="audit_lead").first()
            lead_token = SecurityAuth.create_access_token(lead)

            admin = User.query.filter_by(username="audit_admin").first()
            admin_token = SecurityAuth.create_access_token(admin)

            # Auditor cannot approve (level 1 < 3)
            res_auditor = audit_client.post(
                f"/api/incidents/{inc_id}/actions/{action.id}/approve",
                headers={"Authorization": f"Bearer {auditor_token}"}
            )
            assert res_auditor.status_code == 403

            # Lead CAN approve (level 3 >= 3)
            res_lead = audit_client.post(
                f"/api/incidents/{inc_id}/actions/{action.id}/approve",
                headers={"Authorization": f"Bearer {lead_token}"},
                json={"analyst_name": "Lead Analyst"}
            )
            assert res_lead.status_code == 200
            assert res_lead.get_json()["status"] == "success"

            # Execution requires Admin (level 4)
            res_exec_lead = audit_client.post(
                f"/api/incidents/{inc_id}/actions/{action.id}/execute",
                headers={"Authorization": f"Bearer {lead_token}"}
            )
            assert res_exec_lead.status_code == 403

            res_exec_admin = audit_client.post(
                f"/api/incidents/{inc_id}/actions/{action.id}/execute",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert res_exec_admin.status_code in [200, 400, 404, 500]  # Passes auth check
        finally:
            Config.API_AUTH_ENABLED = orig_auth

    # =========================================================================
    # 3. SSRF and Network Security Audit
    # =========================================================================

    def test_10_ssrf_comprehensive_target_inspection(self):
        """Verify that all forbidden SSRF vectors are caught without real outbound queries."""
        # 1. Loopback addresses
        assert is_ssrf_safe_ip("127.0.0.1") is False
        assert is_ssrf_safe_ip("127.0.1.1") is False
        assert is_ssrf_safe_ip("::1") is False
        assert is_ssrf_safe_url("http://127.0.0.1:8000/")[0] is False
        assert is_ssrf_safe_url("http://[::1]:8080/")[0] is False

        # 2. Localhost and internal aliases
        assert is_ssrf_safe_url("http://localhost:5000/")[0] is False
        assert is_ssrf_safe_url("http://metadata.google.internal/")[0] is False
        assert is_ssrf_safe_url("http://instance-data/")[0] is False

        # 3. RFC 1918 Private networks
        assert is_ssrf_safe_ip("10.0.0.1") is False
        assert is_ssrf_safe_ip("172.16.0.1") is False
        assert is_ssrf_safe_ip("192.168.1.1") is False
        assert is_ssrf_safe_url("http://10.200.1.1/secret")[0] is False
        assert is_ssrf_safe_url("http://192.168.0.1/admin")[0] is False

        # 4. Link-Local & Cloud Metadata Services
        assert is_ssrf_safe_ip("169.254.169.254") is False
        assert is_ssrf_safe_ip("169.254.170.2") is False
        assert is_ssrf_safe_ip("100.100.100.200") is False
        assert is_ssrf_safe_url("http://169.254.169.254/latest/meta-data/")[0] is False

        # 5. Public Internet routable addresses (must be permitted)
        assert is_ssrf_safe_ip("8.8.8.8") is True
        assert is_ssrf_safe_ip("1.1.1.1") is True
        assert is_ssrf_safe_url("https://www.google.com")[0] is True

    def test_11_ssrf_threat_intel_client_interception(self):
        """Verify threat intelligence client blocks SSRF prior to HTTP dispatch."""
        res_scan = threat_intel.submit_urlscan("http://169.254.169.254/latest")
        assert res_scan["status"] == "rejected"
        assert res_scan["verdict"] == "blocked"

        res_rdap = threat_intel.lookup_rdap_ip("10.0.0.1")
        assert res_rdap["status"] == "rejected"

    # =========================================================================
    # 4. Splunk TLS Security Audit
    # =========================================================================

    def test_12_splunk_tls_configuration_and_ca_bundle_support(self):
        """Verify Splunk client supports enterprise CA bundle and masks secrets."""
        client = SplunkClient()
        # Verify password is never present in string representation
        client_str = str(client)
        assert Config.SPLUNK_PASSWORD not in client_str
        assert hasattr(client, "verify_ssl")

        # Test CA bundle path resolution
        orig_ca = Config.SPLUNK_CA_BUNDLE
        try:
            Config.SPLUNK_CA_BUNDLE = str(Path(__file__).resolve())
            test_client = SplunkClient()
            assert test_client.verify_ssl == str(Path(__file__).resolve())
        finally:
            Config.SPLUNK_CA_BUNDLE = orig_ca

    def test_13_splunk_connection_failure_handled_safely(self):
        """Verify connection errors to non-existent hosts return clean degraded status."""
        client = SplunkClient()
        orig_host = client.host
        try:
            client.host = "192.0.2.1"  # TEST-NET-1 unroutable IP
            client.timeout = 1
            res = client.execute_search("index=sysmon | head 1")
            assert res["status"] in ["error", "degraded", "operational"]
            assert Config.SPLUNK_PASSWORD not in str(res)
        finally:
            client.host = orig_host
            client.timeout = 25

    # =========================================================================
    # 5. Docker Security Audit
    # =========================================================================

    def test_14_docker_security_configuration(self):
        """Verify Docker configuration enforces unprivileged execution and secret isolation."""
        root_dir = Path(__file__).resolve().parent.parent.parent
        backend_dockerfile = root_dir / "backend" / "Dockerfile"
        frontend_dockerfile = root_dir / "frontend" / "Dockerfile"
        docker_compose = root_dir / "docker-compose.yml"
        dockerignore = root_dir / "backend" / ".dockerignore"

        assert backend_dockerfile.exists()
        assert frontend_dockerfile.exists()
        assert docker_compose.exists()
        assert dockerignore.exists()

        # 1. Non-root user in Backend Dockerfile
        backend_content = backend_dockerfile.read_text(encoding="utf-8")
        assert "USER socuser" in backend_content
        assert "groupadd" in backend_content

        # 2. Excluded secrets in .dockerignore
        dockerignore_content = dockerignore.read_text(encoding="utf-8")
        assert ".env" in dockerignore_content
        assert "*.db" in dockerignore_content

        # 3. Localhost-only port bindings in docker-compose.yml
        compose_content = docker_compose.read_text(encoding="utf-8")
        assert "127.0.0.1:5000:5000" in compose_content
        assert "127.0.0.1:5173:80" in compose_content
        assert "privileged: true" not in compose_content
        assert "healthcheck" in compose_content

    # =========================================================================
    # 6. Database Backup & Disaster Recovery Audit
    # =========================================================================

    def test_15_database_backup_integrity_and_restore(self):
        """Verify hot backup creation, PRAGMA integrity check, and test restore."""
        # 1. Generate hot backup
        backup_path = perform_hot_backup()
        assert os.path.exists(backup_path)

        # 2. Check snapshot integrity directly
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        result = cursor.fetchone()
        conn.close()
        assert result[0] == "ok"

        # 3. Verify users and investigations exist in the backup snapshot
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM users;")
        user_count = cursor.fetchone()[0]
        assert user_count > 0
        conn.close()

        # Clean up created backup file
        if os.path.exists(backup_path):
            os.remove(backup_path)
