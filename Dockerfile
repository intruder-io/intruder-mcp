FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/intruder-io/intruder-mcp"

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache uv sync --locked --no-dev --no-install-project

COPY . .
RUN --mount=type=cache,target=/root/.cache uv sync --locked --no-dev

# Not `uv run`: it re-syncs from PyPI on start, and even with --no-sync needs a writable cache dir,
# which breaks read-only and non-root containers.
CMD ["/app/.venv/bin/intruder-mcp"]
