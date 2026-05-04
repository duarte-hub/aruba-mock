"""Idempotent DB initialization called from entrypoint.sh."""
from __future__ import annotations

import logging

from app.db import Base, get_engine
from app import models  # noqa: F401  -- ensure models are registered

log = logging.getLogger("aruba.db_init")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def main() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    log.info("Schema ensured at %s", engine.url)


if __name__ == "__main__":
    main()
