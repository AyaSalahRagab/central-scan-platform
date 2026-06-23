FROM python:3.11-slim

# Install system dependencies: tar, curl, and build essentials (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Opengrep
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
ENV PATH="/root/.opengrep/cli/latest:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and template
COPY . .

# Environment variables (can be overridden at runtime)
ENV UPLOAD_DIR=/tmp/security_scans \
    REPORT_DIR=/app/reports \
    TRIVY_TEMPLATE=/app/trivy-html.tpl \
    REDIS_URL=redis://redis:6379/0

# Create directories
RUN mkdir -p ${UPLOAD_DIR} ${REPORT_DIR}

# Expose port for FastAPI
EXPOSE 8000

# Default command (overridden in compose)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]