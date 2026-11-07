from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..models import db, User
from ..extensions import limiter
from ..utils.auth import SecurityAuth, require_auth

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/login", methods=["POST"])
@limiter.limit(Config.RATELIMIT_AUTH)
def login():
    """
    Analyst authentication endpoint.
    Verifies credentials against PBKDF2:SHA256 salted hashes,
    enforces rate limiting, and issues cryptographically signed JWT session tokens.
    """
    data = request.get_json(silent=True) or {}
    identity = (data.get("username") or data.get("email") or "").strip()
    password = data.get("password", "")

    if not identity or not password:
        return jsonify({"error": "Username/email and password are required.", "status": 400}), 400

    user = User.query.filter((User.username == identity) | (User.email == identity)).first()

    if not user:
        # Constant-time mitigation against user enumeration
        User().set_password("dummy-password-for-timing")
        return jsonify({"error": "Invalid credentials.", "status": 401}), 401

    if not user.is_active:
        return jsonify({"error": "Account is disabled. Contact SOC administrator.", "status": 403}), 403

    if user.is_locked():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        return jsonify({
            "error": f"Account is temporarily locked due to excessive failed attempts. Try again in {remaining} minutes.",
            "status": 423
        }), 423

    if not user.check_password(password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= Config.MAX_FAILED_LOGINS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=Config.ACCOUNT_LOCKOUT_MINUTES)
        db.session.commit()
        return jsonify({"error": "Invalid credentials.", "status": 401}), 401

    # Login succeeded: reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()

    token = SecurityAuth.create_access_token(user)

    return jsonify({
        "status": "success",
        "message": "Authentication successful.",
        "token": token,
        "token_type": "Bearer",
        "expires_in_hours": Config.JWT_EXPIRATION_HOURS,
        "user": user.to_dict()
    }), 200

@auth_bp.route("/me", methods=["GET"])
@require_auth(required_role="auditor")
def get_current_profile():
    """Returns profile information for the authenticated user session."""
    user_payload = getattr(g, "current_user", {})
    sub = user_payload.get("sub")
    
    if sub and sub.isdigit():
        user = db.session.get(User, int(sub))
        if user:
            return jsonify({"status": "success", "user": user.to_dict()}), 200

    return jsonify({
        "status": "success",
        "user": {
            "username": user_payload.get("username", "analyst"),
            "role": user_payload.get("role", "analyst")
        }
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
@require_auth(required_role="auditor")
def refresh_token():
    """Issues a refreshed JWT session token for the active user."""
    user_payload = getattr(g, "current_user", {})
    sub = user_payload.get("sub")
    if sub and sub.isdigit():
        user = db.session.get(User, int(sub))
        if user and user.is_active and not user.is_locked():
            new_token = SecurityAuth.create_access_token(user)
            return jsonify({
                "status": "success",
                "token": new_token,
                "token_type": "Bearer",
                "expires_in_hours": Config.JWT_EXPIRATION_HOURS
            }), 200

    return jsonify({"error": "Unable to refresh token.", "status": 401}), 401

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Revokes the active session token and terminates the session."""
    auth_header = request.headers.get("Authorization", "").strip()
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if token:
        SecurityAuth.revoke_token(token)

    return jsonify({
        "status": "success",
        "message": "Session terminated and token revoked successfully."
    }), 200

@auth_bp.route("/users", methods=["GET"])
@require_auth(required_role="admin")
def list_users():
    """Lists all registered analyst accounts (Admin only)."""
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({
        "status": "success",
        "users": [u.to_dict() for u in users]
    }), 200

@auth_bp.route("/users", methods=["POST"])
@require_auth(required_role="admin")
def create_user():
    """Provisions a new analyst account with designated RBAC role (Admin only)."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password", "")
    role = (data.get("role") or "analyst").strip().lower()

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required.", "status": 400}), 400

    if role not in SecurityAuth.ROLE_HIERARCHY:
        return jsonify({
            "error": f"Invalid role '{role}'. Valid roles: {list(SecurityAuth.ROLE_HIERARCHY.keys())}",
            "status": 400
        }), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "User with this username or email already exists.", "status": 409}), 409

    try:
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": f"User '{username}' created with role '{role}'.",
            "user": new_user.to_dict()
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e), "status": 400}), 400

