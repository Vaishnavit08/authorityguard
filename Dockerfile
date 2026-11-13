FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY apps ./apps
COPY migrations ./migrations
RUN pip install --no-cache-dir ".[postgres]"

# Run as non-root. .keys holds the dev signing key; mount a real key there outside dev.
RUN useradd --create-home --uid 10001 app && mkdir -p /app/.keys && chown app /app/.keys
USER app

EXPOSE 8000
# Apply schema migrations, then serve.
CMD ["sh", "-c", "alembic upgrade head && uvicorn apps.api.main:app --host 0.0.0.0 --port 8000"]
