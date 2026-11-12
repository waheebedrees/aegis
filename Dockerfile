# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

# ── builder: deps + source, shared by dev and prod ─────────────────────────
FROM ${PYTHON_IMAGE} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY libs/pyproject.toml          ./libs/

COPY aegis/services/orchestrator/pyproject.toml ./services/orchestrator/
COPY aegis/services/worker/pyproject.toml       ./services/worker/
COPY aegis/services/tools/pyproject.toml        ./services/tools/
COPY aegis/services/llm-gateway/pyproject.toml  ./services/llm-gateway/

ARG SERVICE=orchestrator

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package ${SERVICE} \
            --no-install-project --no-install-workspace

COPY libs/agentid        ./libs/agentid
COPY libs/transport      ./libs/transport
COPY libs/capchain      ./libs/capchain
COPY aegis/services/${SERVICE} ./services/${SERVICE}

# ── builder-dev: editable installs (uv default) + file watcher ─────────────
FROM builder AS builder-dev
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package ${SERVICE} \
 && uv pip install --python /app/.venv/bin/python watchfiles

# ── builder-prod: non-editable, venv works without the source ──────────────
FROM builder AS builder-prod
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package ${SERVICE}

# ── runtime-base: user + env, shared by dev and prod ───────────────────────
FROM ${PYTHON_IMAGE} AS runtime-base

ARG UID=10001
ARG GID=10001
ARG SERVICE=default

RUN groupadd -g ${GID} ${SERVICE} \
 && useradd  -m -u ${UID} -g ${GID} -s /bin/bash ${SERVICE} \
 && mkdir -p /run/svid && chown ${UID}:${GID} /run/svid

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SERVICE=${SERVICE}

USER ${UID}:${GID}
EXPOSE 8443

# ── dev: FLAT layout — /app/main.py, /app/libs/, /app/.venv only ───────────
# No /app/services/ directory  no way for compose to expose other services.
FROM runtime-base AS dev
COPY --from=builder-dev --chown=${UID}:${GID} /app/.venv /app/.venv
COPY --chown=${UID}:${GID} aegis/services/${SERVICE}/. /app/
CMD ["sh", "-c", "exec watchfiles --filter python 'python main.py' /app"]

# ── runtime: prod (last stage = default target) ────────────────────────────
FROM runtime-base AS runtime
COPY --from=builder-prod --chown=${UID}:${GID} /app/.venv /app/.venv
COPY --chown=${UID}:${GID} aegis/services/${SERVICE}/. /app/
ENTRYPOINT ["python", "/app/main.py"]