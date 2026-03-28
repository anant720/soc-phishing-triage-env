ARG BASE_IMAGE=openenv-base:latest
FROM ${BASE_IMAGE}

# We need the source code installed into the container
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy the entire repository into /app
COPY . /app/
WORKDIR /app

# Ensure we have the local package context
ENV PYTHONPATH=/app/src:$PYTHONPATH

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "soc_triage_env.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
