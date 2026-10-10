# Build stage. uv is pinned to the version in pyproject.toml's required-version,
# and dependencies install from the committed lockfile.
FROM python:3.13.14-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.12.15 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Dependencies first, so a source change does not reinstall the world.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev

# Runtime stage.
FROM python:3.13.14-slim

# A non-root user with no login shell and no home directory to write into.
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin detector

WORKDIR /app
COPY --from=build --chown=65532:65532 /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 65532:65532

EXPOSE 9000
CMD ["uvicorn", "translation_guard.api:app", "--host", "0.0.0.0", "--port", "9000"]
