# Aruba Central mock — single container
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps:
#   - build-essential + libffi/libssl: needed by cryptography (paramiko/netmiko)
#   - iputils-ping: for ICMP reachability checks
#   - libsnmp-dev / snmp / snmp-mibs-downloader: useful for snmpwalk debugging from inside the container
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        iputils-ping \
        snmp \
        snmp-mibs-downloader \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --create-home --uid 1000 aruba

WORKDIR /app

# Install Python deps first for better layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Copy app
COPY app /app/app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent data dir (SQLite, secrets, etc.)
RUN mkdir -p /data && chown -R aruba:aruba /data /app

USER aruba

ENV ARUBA_DB_PATH=/data/aruba.db \
    ARUBA_HOST=0.0.0.0 \
    ARUBA_PORT=8080 \
    ARUBA_POLL_INTERVAL=60 \
    ARUBA_LOG_LEVEL=info

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
