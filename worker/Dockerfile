FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including Docker CLI and Nmap
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    nmap \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for running containerized tools)
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
    sh get-docker.sh && \
    rm get-docker.sh

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create artifacts directory
RUN mkdir -p /app/artifacts

CMD ["celery", "-A", "tasks", "worker", "--loglevel=info"]

