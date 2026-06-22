# apt-fl-coordinator — standalone federated aggregation server.
FROM python:3.12-slim

# Non-root runtime user.
RUN useradd -m -u 1000 flcoord

WORKDIR /app

# Dependencies first for layer caching.
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt

# Application code (no monorepo packages — fully self-contained).
COPY flproto/      flproto/
COPY coordinator/  coordinator/
COPY client_ref/   client_ref/
COPY config/       config/

# Pre-create the runtime data dir owned by flcoord. A fresh named volume mounted
# at /app/data inherits this ownership, so the non-root user can write the CA /
# DB / models. Without this, init_ca fails with PermissionError on /app/data/ca
# (a fresh named volume is root-owned, and the service drops CAP_CHOWN).
RUN mkdir -p /app/data && chown -R flcoord:flcoord /app/data

USER flcoord

EXPOSE 8889

# Default command is overridden by docker-compose to wire in TLS/mTLS flags.
# Bare form (no TLS) is for local/dev only.
CMD ["python", "-m", "uvicorn", "coordinator.app:app", "--host", "0.0.0.0", "--port", "8889"]
