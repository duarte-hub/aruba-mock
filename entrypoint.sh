#!/usr/bin/env bash
set -euo pipefail

# Ensure the data dir exists and is writable
mkdir -p /data

# Initialize DB schema on first boot (idempotent)
python -m app.db_init

exec "$@"
