# Falcon MAG - Backend Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    pydantic-settings \
    "pyjwt[crypto]" \
    bcrypt \
    passlib \
    python-multipart \
    "httpx[http2]" \
    aiosqlite \
    dnslib \
    structlog \
    rich \
    typer \
    anthropic \
    reportlab \
    jinja2 \
    aiohttp \
    python-Levenshtein \
    playwright

# Copy application
COPY . /app/

# Create directories for data
RUN mkdir -p /app/data /app/reports /app/bug_bounty_reports

# Expose port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8888/api/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8888"]