# syntax=docker/dockerfile:1

# === STAGE 1: build ===
FROM python:3.12-slim AS build
# Copy uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1
WORKDIR /app
# Copy dependency files to leverage layer caching
COPY pyproject.toml uv.lock ./
# Install dependencies into .venv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project
# Copy source code
COPY . .
# Install the project itself
RUN uv sync --frozen

# === STAGE 2: runtime ===
FROM python:3.12-slim AS runtime
WORKDIR /app
# Copy virtual environment and source code from build stage
COPY --from=build /app/.venv /app/.venv
# Copy Python files and src directory
COPY --from=build /app/*.py /app/
COPY --from=build /app/src /app/src
# Ensure scripts are in PATH
ENV PATH="/app/.venv/bin:$PATH"
# Default command (will be overridden in docker-compose.yml)
CMD ["gunicorn", "--bind", "0.0.0.0:9000", "--access-logfile", "-", "--error-logfile", "-", "oidc_prod_lab:create_idp()"]
