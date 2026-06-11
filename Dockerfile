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

USER flcoord

EXPOSE 8889

# Default command is overridden by docker-compose to wire in TLS/mTLS flags.
# Bare form (no TLS) is for local/dev only.
CMD ["python", "-m", "uvicorn", "coordinator.app:app", "--host", "0.0.0.0", "--port", "8889"]
