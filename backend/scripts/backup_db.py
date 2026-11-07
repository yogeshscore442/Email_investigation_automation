"""
PhishScope SOC - Database Security & Hot Backup Utility
Performs online, lock-free SQLite backups and integrity checks for production disaster recovery.
"""

import os
import sys
import sqlite3
import shutil
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "instance" / "email_investigation.db"
if not DB_PATH.exists():
    DB_PATH = BASE_DIR / "email_investigation.db"
BACKUP_DIR = BASE_DIR / "data" / "backups"

def perform_hot_backup() -> str:
    """Performs an online, transactionally consistent hot backup of the SQLite database."""
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Source database not found at {DB_PATH}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_file = BACKUP_DIR / f"phishscope_backup_{timestamp}.db"

    # Use SQLite Online Backup API for lock-free snapshot
    src_conn = sqlite3.connect(str(DB_PATH))
    dst_conn = sqlite3.connect(str(backup_file))

    with dst_conn:
        src_conn.backup(dst_conn, pages=100)

    dst_conn.close()
    src_conn.close()

    # Perform integrity verification on the generated snapshot
    verify_conn = sqlite3.connect(str(backup_file))
    cursor = verify_conn.cursor()
    cursor.execute("PRAGMA integrity_check;")
    result = cursor.fetchone()
    verify_conn.close()

    if result and result[0] == "ok":
        # Restrict permissions if on POSIX
        try:
            os.chmod(str(backup_file), 0o600)
        except Exception:
            pass
        return str(backup_file)
    else:
        if backup_file.exists():
            os.remove(backup_file)
        raise RuntimeError(f"Integrity check failed for backup: {result}")

def restore_backup(backup_path: str):
    """Restores database from a verified backup snapshot."""
    b_path = Path(backup_path)
    if not b_path.exists():
        raise FileNotFoundError(f"Backup file not found at {b_path}")

    # Verify integrity before restoring
    verify_conn = sqlite3.connect(str(b_path))
    cursor = verify_conn.cursor()
    cursor.execute("PRAGMA integrity_check;")
    result = cursor.fetchone()
    verify_conn.close()

    if not result or result[0] != "ok":
        raise ValueError(f"Backup file failed integrity check: {result}")

    # Create safety snapshot of current database
    if DB_PATH.exists():
        safety_path = DB_PATH.with_suffix(".pre_restore.bak")
        shutil.copy2(DB_PATH, safety_path)

    shutil.copy2(b_path, DB_PATH)
    return True

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--restore":
        target = sys.argv[2]
        restore_backup(target)
        print(f"[+] Successfully restored database from {target}")
    else:
        path = perform_hot_backup()
        print(f"[+] Hot backup created and verified: {path}")

