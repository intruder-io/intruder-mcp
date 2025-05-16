# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set the source URL for the image
LABEL org.opencontainers.image.source="https://github.com/intruder-io/intruder-mcp"

# Copy the project into the image
ADD . /app

# Sync the project into a new environment, asserting the lockfile is up to date
WORKDIR /app
RUN uv sync && uv pip install -e .

# Presuming there is a `my_app` command provided by the project
CMD ["uv", "--directory", "intruder_mcp", "run", "server.py"]
