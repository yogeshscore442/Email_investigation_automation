import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-soc-analyst-environment-32chars")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'email_investigation.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"timeout": 30}
    }
    
    # Upload & Storage
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25")) * 1024 * 1024
    STORAGE_DIR = BASE_DIR / "data" / "storage"
    SAMPLES_DIR = BASE_DIR / "data" / "samples"

    # Authentication & Access Control
    API_AUTH_ENABLED = os.getenv("ENABLE_AUTH", "false").lower() == "true"
    API_KEY = os.getenv("API_KEY", "soc-analyst-secret-key-2026").strip()
    ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "soc-admin-secret-key-2026").strip()
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY).strip()
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "8"))
    MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
    ACCOUNT_LOCKOUT_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "15"))

    # CORS & Network Boundaries
    CORS_ORIGINS = [orig.strip() for orig in os.getenv("CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:5000,http://localhost:5000").split(",") if orig.strip()]

    # Rate Limiting
    ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "120 per minute")
    RATELIMIT_UPLOAD = os.getenv("RATELIMIT_UPLOAD", "30 per minute")
    RATELIMIT_AUTH = os.getenv("RATELIMIT_AUTH", "10 per minute")
    
    # Threat Intelligence Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
    
    # AI Keys (Supports OpenAI and Gemini)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
    AI_API_KEY = os.getenv("AI_API_KEY", "").strip() or OPENAI_API_KEY
    AI_PROVIDER = os.getenv("AI_PROVIDER", "openai" if OPENAI_API_KEY else "gemini").strip().lower()
    AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini" if (AI_PROVIDER == "openai" or OPENAI_API_KEY) else "gemini-1.5-flash").strip()
    
    # SIEM Integrations (Splunk & Wazuh)
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "").strip()
    SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "").strip()
    SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "").strip()
    SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "").strip()
    SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "sysmon").strip()
    SPLUNK_INDEXES = [idx.strip() for idx in os.getenv("SPLUNK_INDEXES", "sysmon,windows,powershell").split(",") if idx.strip()]
    SPLUNK_SSL_VERIFY = os.getenv("SPLUNK_SSL_VERIFY", "false").lower() == "true"
    SPLUNK_CA_BUNDLE = os.getenv("SPLUNK_CA_BUNDLE", "").strip()

    WAZUH_HOST = os.getenv("WAZUH_HOST", "").strip()
    WAZUH_PORT = int(os.getenv("WAZUH_PORT", "55000"))
    WAZUH_USER = os.getenv("WAZUH_USER", "").strip()
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "").strip()
    WAZUH_SSL_VERIFY = os.getenv("WAZUH_SSL_VERIFY", "false").lower() == "true"
    
    # High-value Target Brands for Lookalike / Typosquatting Detection
    TARGETED_BRANDS = [
        "microsoft", "office365", "outlook", "azure", "sharepoint", "onedrive",
        "google", "gmail", "workspace", "apple", "icloud", "amazon", "aws",
        "paypal", "chase", "bankofamerica", "wellsfargo", "citibank",
        "docusign", "dropbox", "netflix", "adobe", "dhl", "fedex", "ups",
        "stripe", "coinbase", "binance", "metamask", "facebook", "meta",
        "linkedin", "zoom", "slack", "github", "gitlab", "jira", "atlassian"
    ]
    
    # Suspicious Top-Level Domains commonly abused in spam/phishing
    SUSPICIOUS_TLDS = {
        "xyz", "top", "icu", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
        "work", "click", "rest", "country", "stream", "bid", "loan", "men",
        "date", "party", "review", "trade", "accountant", "faith", "download",
        "racing", "cricket", "win", "support", "vip", "fit", "website", "online"
    }
    
    # High-Risk File Extensions
    DANGEROUS_EXTENSIONS = {
        # Executables & Installers
        ".exe", ".scr", ".bat", ".cmd", ".cpl", ".msi", ".msp", ".pif", ".com",
        # Scripts
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar",
        # Disk Images & Containers (Bypass Mark-of-the-Web)
        ".iso", ".img", ".vhd", ".vhdx", ".7z", ".rar", ".tar", ".gz",
        # Macro-Enabled Office Files
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam",
        # Linux / Unix scripts
        ".sh", ".bash", ".bin", ".elf"
    }

    # Ensure storage paths exist
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

