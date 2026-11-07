import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from .investigation import db

class User(db.Model):
    """
    User Account model for SOC Analysts, Incident Leads, and Administrators.
    Stores cryptographically salted password hashes and tracks login security.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")  # admin, lead, analyst, auditor
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str):
        """Hashes password using PBKDF2:SHA256 with cryptographically strong salt."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")

    def check_password(self, password: str) -> bool:
        """Verifies plain password against stored salted hash in constant time."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Checks if account is locked due to excessive failed attempts."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def to_dict(self) -> dict:
        """Serializes user info for API responses, strictly omitting password hash."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "is_locked": self.is_locked(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }

