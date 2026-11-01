"""Check that PostgreSQL is reachable with the project settings.

Usage: uv run python -m scripts.check_postgres
"""

from __future__ import annotations

import sys

from sqlalchemy import create_engine, text

from core.config import get_settings


def main() -> int:
    engine = create_engine(get_settings().database_url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as conn:
            version = conn.execute(text("select version()")).scalar_one()
    except Exception as exc:  # noqa: BLE001 - report the error type without credentials
        print(f"FAILED: {type(exc).__name__}")
        return 1
    print(f"ok: {str(version).split(',')[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
