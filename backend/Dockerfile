FROM python:3.12-slim AS base

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/backend/.venv/bin:$PATH"

RUN pip install "poetry==1.8.3"

WORKDIR /backend

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.in-project true \
    && poetry install --only main --no-root --no-interaction --no-ansi

COPY . .

RUN poetry install --only main --no-interaction --no-ansi

# Run as non-root user.
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=172.0.0.0/8"]
