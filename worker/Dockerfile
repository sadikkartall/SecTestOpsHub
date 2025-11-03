FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    nmap \
    curl \
    wget \
    git \
    perl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    build-essential \
    libssl-dev \
    dnsutils \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for running containerized tools)
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
    sh get-docker.sh && \
    rm get-docker.sh

# Install Go (required for Amass and ffuf)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install Nikto from GitHub
RUN git clone https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install Amass
RUN go install -v github.com/owasp-amass/amass/v4/...@master && \
    ln -s /root/go/bin/amass /usr/local/bin/amass

# Install ffuf
RUN go install github.com/ffuf/ffuf/v2@latest && \
    ln -s /root/go/bin/ffuf /usr/local/bin/ffuf

# Install WhatWeb from GitHub
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# Download common wordlist for ffuf
RUN mkdir -p /usr/share/wordlists && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /usr/share/wordlists/common.txt

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create artifacts directory
RUN mkdir -p /app/artifacts

CMD ["celery", "-A", "tasks", "worker", "--loglevel=info"]

