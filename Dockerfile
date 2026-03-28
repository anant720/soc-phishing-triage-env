# HF Spaces / OpenEnv Docker build
# Uses a standard Python base since openenv-base may not be on HF's builders
FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a non-root user (HF Spaces best practice)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR /home/user/app

# Copy and install deps first (better layer caching)
COPY --chown=user server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the full project in
COPY --chown=user . .

# Make sure Python can find the root-level modules
ENV PYTHONPATH=/home/user/app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# HF Spaces uses port 7860
EXPOSE 7860

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
