# syntax=docker/dockerfile:1.7


FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock ./


COPY libs/agentid/pyproject.toml         ./libs/agentid/
COPY services/orchestrator/pyproject.toml ./services/orchestrator/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package orchestrator \
            --no-install-project --no-install-workspace

COPY libs/agentid           ./libs/agentid
COPY services/orchestrator  ./services/orchestrator

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package orchestrator

FROM python:3.12-slim
RUN groupadd -g 10001 app && useradd -u 10001 -g app -m app
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 services/orchestrator/main.py /app/main.py
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 9443
ENTRYPOINT ["python", "/app/main.py"]