import os
from pathlib import Path
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from .config import Config
from .models import db, User
from .extensions import limiter
from .routes import investigate_bp, dashboard_bp, incidents_bp, phase5_bp, auth_bp

def create_app(config_class=Config):
    dist_dir = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    
    if dist_dir.exists():
        app = Flask(__name__, static_folder=str(dist_dir / "assets"), static_url_path="/assets")
    else:
        app = Flask(__name__)
        
    app.config.from_object(config_class)

    # Secure CORS configuration: explicit origins, credentials support
    allowed_origins = getattr(config_class, "CORS_ORIGINS", ["*"])
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, supports_credentials=True)

    # Initialize Database & Rate Limiter
    db.init_app(app)
    limiter.init_app(app)

    # Register Blueprints
    app.register_blueprint(investigate_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(phase5_bp)
    app.register_blueprint(auth_bp)

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self' http://127.0.0.1:5000 http://localhost:5000 http://127.0.0.1:5173 http://localhost:5173; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Serve Frontend Single-Page Application (SPA) if built
    if dist_dir.exists():
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_spa(path):
            if path != "" and (dist_dir / path).exists():
                return send_from_directory(dist_dir, path)
            return send_from_directory(dist_dir, "index.html")

    # Error handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({
            "error": "Uploaded file exceeds maximum permitted size (25MB limit).",
            "status": 413
        }), 413

    @app.errorhandler(429)
    def ratelimit_exceeded(error):
        return jsonify({
            "error": "Rate limit exceeded. Please throttle your security queries.",
            "status": 429
        }), 429

    @app.errorhandler(404)
    def not_found(error):
        # If frontend SPA exists, let SPA handle route
        if dist_dir.exists():
            return send_from_directory(dist_dir, "index.html")
        return jsonify({"error": "Resource not found.", "status": 404}), 404

    @app.errorhandler(500)
    def internal_error(error):
        import uuid
        req_id = str(uuid.uuid4())[:8]
        app.logger.error(f"Internal server error [req_id={req_id}]: {error}")
        return jsonify({
            "error": "An internal server error occurred.",
            "request_id": req_id,
            "status": 500
        }), 500

    # Ensure tables exist and schema is up-to-date
    with app.app_context():
        db.create_all()
        # Safe schema migration and SQLite security pragmas
        try:
            from sqlalchemy import text
            # Enable WAL mode for high concurrency and foreign keys
            db.session.execute(text("PRAGMA journal_mode=WAL;"))
            db.session.execute(text("PRAGMA foreign_keys=ON;"))
            
            res = db.session.execute(text("PRAGMA table_info(extracted_iocs)")).fetchall()
            existing_cols = [row[1] for row in res]
            if existing_cols:
                if "provider" not in existing_cols:
                    db.session.execute(text("ALTER TABLE extracted_iocs ADD COLUMN provider VARCHAR(50) DEFAULT 'heuristic'"))
                if "confidence" not in existing_cols:
                    db.session.execute(text("ALTER TABLE extracted_iocs ADD COLUMN confidence INTEGER DEFAULT 0"))
                if "lookup_timestamp" not in existing_cols:
                    db.session.execute(text("ALTER TABLE extracted_iocs ADD COLUMN lookup_timestamp VARCHAR(50) DEFAULT ''"))
                if "api_status" not in existing_cols:
                    db.session.execute(text("ALTER TABLE extracted_iocs ADD COLUMN api_status VARCHAR(50) DEFAULT 'not_queried'"))
            db.session.commit()

            # Seed initial SOC analyst and admin accounts if database is empty
            if User.query.count() == 0:
                default_users = [
                    ("admin", "admin@soc.local", "AdminPassword2026!Secure", "admin"),
                    ("lead", "lead@soc.local", "LeadPassword2026!Secure", "lead"),
                    ("analyst", "analyst@soc.local", "AnalystPassword2026!Secure", "analyst"),
                ]
                for uname, uemail, upass, urole in default_users:
                    u = User(username=uname, email=uemail, role=urole)
                    u.set_password(upass)
                    db.session.add(u)
                db.session.commit()
        except Exception as e:
            db.session.rollback()

    return app

    return app
