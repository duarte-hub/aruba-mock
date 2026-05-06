"""Idempotent DB initialization called from entrypoint.sh."""
from __future__ import annotations

import logging

from sqlalchemy import text

from app.db import Base, get_engine
from app import models  # noqa: F401  -- ensure models are registered

log = logging.getLogger("aruba.db_init")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

# Columns added to existing tables after initial release.
# SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we try/ignore.
_COLUMN_MIGRATIONS = [
    ("switch_ports", "mac_address TEXT"),
    ("switch_ports", "mac_vendor TEXT"),
    ("switch_ports", "lldp_neighbor TEXT"),
    ("switch_ports", "lldp_neighbor_port TEXT"),
    ("switch_ports", "in_errors INTEGER"),
    ("switch_ports", "out_errors INTEGER"),
    ("switch_ports", "in_discards INTEGER"),
]


def _migrate_columns(engine) -> None:
    with engine.connect() as conn:
        for table, col_def in _COLUMN_MIGRATIONS:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_def}"))
                conn.commit()
                log.info("migrated: added %s.%s", table, col_def.split()[0])
            except Exception:
                pass  # column already exists


def main() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    _migrate_columns(engine)
    log.info("Schema ensured at %s", engine.url)


if __name__ == "__main__":
    main()
