# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY libs/agentid/pyproject.toml            ./libs/agentid/
COPY cli/agentctl/pyproject.toml            ./cli/agentctl/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package agentctl \
            --no-install-project --no-install-workspace

COPY libs/agentid      ./libs/agentid
COPY cli/agentctl      ./cli/agentctl

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package agentctl

FROM python:3.12-slim
RUN groupadd -g 10001 app && useradd -u 10001 -g app -m app
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
USER 10001
ENTRYPOINT ["agentctl"]
CMD ["--help"]