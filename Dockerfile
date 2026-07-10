FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

COPY --chown=appuser:appgroup . .

USER appuser

# Default entrypoint runs the API.
# Override `command` in docker-compose.yml to run the worker instead.
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
