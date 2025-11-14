"""Quick MySQL connection test for SecureChat.

- Loads .env if present
- Connects using app.storage.db.get_conn()
- Ensures users table exists (init_db)
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# Ensure imports work when running as a script
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from storage import db as dbmod


def main() -> int:
    try:
        dbmod.init_db()
        with dbmod.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DATABASE()")
                dbname = cur.fetchone()[0]
                cur.execute("SHOW TABLES LIKE 'users'")
                has_users = cur.fetchone() is not None
        print(f"[OK] Connected to MySQL database: {dbname}")
        print(f"[OK] users table exists: {has_users}")
        return 0
    except Exception as e:
        print(f"[ERROR] DB test failed: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
