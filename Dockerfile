# HF Spaces / OpenEnv Docker build
# Default CMD: FastAPI REST API on port 7860 (required for openenv validate + judge automation)
# For interactive Gradio demo: docker run -e GRADIO_DEMO=1 ...
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

# Copy the full project
COPY --chown=user . .

# Python module resolution
ENV PYTHONPATH=/home/user/app

# (DB is pre-built and included as data/triage_scenarios.db)

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

EXPOSE 7860
ENV PORT=7860

# Default: FastAPI REST API (required by openenv validate and judge automation)
# Set GRADIO_DEMO=1 to run the interactive UI instead
CMD ["sh", "-c", \
     "if [ \"$GRADIO_DEMO\" = '1' ]; then python gradio_demo.py; \
      else uvicorn server.app:app --host 0.0.0.0 --port 7860; fi"]
