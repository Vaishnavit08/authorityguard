FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY apps ./apps
COPY migrations ./migrations
COPY policies ./policies
RUN pip install --no-cache-dir ".[postgres]"

# Run as non-root. .keys holds the signing key (generated in dev/demo; mount a real one
# elsewhere) and data/ holds the default SQLite database.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /app/.keys /app/data \
    && chown app /app/.keys /app/data
USER app

ENV AG_DATABASE_URL=sqlite:////app/data/authorityguard.db
EXPOSE 8000
# Apply schema migrations, then serve. $PORT is set by hosts such as Render.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn apps.api.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers"]
