# SENTRY — single-image deployment.
#
# The image serves both the API and the dashboard from one origin, which is why
# the session cookie can stay SameSite=Lax without any CORS exceptions.
#
#   docker build -t sentry .
#   docker run -p 8000:8000 --env-file .env sentry

FROM python:3.12-slim

# Unbuffered so logs reach the platform's log drain immediately; without it a
# crash can be swallowed because stdout was never flushed.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# curl is used by HEALTHCHECK below and by platform probes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Torch first, from the CPU-only index. The default PyPI wheel bundles the CUDA
# runtime and is several GB — on a machine with no GPU that is pure image bloat
# and a much slower cold start. Installing it here means the `torch==2.2.2` pin
# in requirements.txt is already satisfied and pip leaves it alone.
RUN pip install --no-cache-dir torch==2.2.2 \
    --index-url https://download.pytorch.org/whl/cpu

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY . /app

# Non-root. A high fixed UID rather than a name so bind-mounted volumes have
# predictable ownership across hosts.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sentry \
    && chown -R sentry:sentry /app
USER sentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/api/health" || exit 1

# Single worker, deliberately. Three pieces of state live in the process and
# not in the database: the WebSocket connection registry, the failed-login
# throttle, and the simulator. With multiple workers a client would only get
# live events from whichever worker it happened to connect to, and the login
# throttle would be trivially bypassed by hitting a different worker. Scale by
# running more containers behind a load balancer with sticky sessions, or move
# that state to Redis first.
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
