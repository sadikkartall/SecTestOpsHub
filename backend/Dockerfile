FROM python:3.12-slim

# Ping, whois, nmap için paketler; Nikto, Gobuster ve testssl.sh manuel kurulum; seclists wordlist arşivi GitHub'dan indiriliyor
ARG NIKTO_VERSION=2.5.0
ARG GOBUSTER_VERSION=3.6.0
ARG AMASS_VERSION=5.0.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping \
        whois \
        nmap \
        docker.io \
        curl \
        ca-certificates \
        perl \
        libnet-ssleay-perl \
        libio-socket-ssl-perl \
        git \
        openssl \
        util-linux \
        bsdmainutils \
        procps \
        gawk \
        ldnsutils \
        libidn2-0 \
        socat \
        unzip \
    && curl -L --retry 5 --retry-delay 3 --fail -o /tmp/nikto.tar.gz "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" \
    && tar -xzf /tmp/nikto.tar.gz -C /opt \
    && mv /opt/nikto-${NIKTO_VERSION} /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && mkdir -p /usr/share/seclists/Discovery/Web-Content \
    && curl -L --retry 5 --retry-delay 3 --fail \
        -o /usr/share/seclists/Discovery/Web-Content/common.txt \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    && ( curl -L --retry 5 --retry-delay 3 --fail \
            -o /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        || curl -L --retry 5 --retry-delay 3 --fail \
            -o /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
            "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        || cp /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ) \
    && curl -L --retry 5 --retry-delay 3 --fail -o /tmp/gobuster.tar.gz "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && chmod +x /opt/testssl.sh/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && (cd /opt/theHarvester && (test -f requirements.txt && pip install --no-cache-dir -r requirements.txt || pip install --no-cache-dir ujson requests dnspython netaddr lxml beautifulsoup4 python-dateutil aiohttp aiodns aiofiles aiomultiprocess aiosqlite censys certifi fastapi httpx retrying shodan slowapi uvicorn uvloop PyYAML playwright)) \
    && ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester \
    && chmod +x /usr/local/bin/theHarvester \
    && curl -L --retry 5 --retry-delay 3 --fail -o /tmp/amass.tar.gz "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.tar.gz" \
    && tar -xzf /tmp/amass.tar.gz -C /tmp \
    && mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass \
    && chmod +x /usr/local/bin/amass \
    # Eğer docker CLI apt ile gelmezse statik binary indirip ekle
    && ( command -v docker >/dev/null 2>&1 \
        || ( curl -fsSL --retry 5 --retry-delay 3 --fail \
              -o /tmp/docker.tgz \
              https://download.docker.com/linux/static/stable/x86_64/docker-24.0.9.tgz \
           && tar -xzf /tmp/docker.tgz -C /tmp \
           && mv /tmp/docker/docker /usr/local/bin/docker \
           && chmod +x /usr/local/bin/docker ) ) \
    && rm -rf /tmp/docker.tgz /tmp/docker \
    && rm -rf /tmp/nikto.tar.gz /tmp/gobuster.tar.gz /tmp/amass.tar.gz /tmp/amass_linux_amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Temel bağımlılıkların kurulumu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir dnsrecon

# Uygulama kaynaklarının kopyalanması
COPY src ./src

# Varsayılan port ve komut
ENV APP_HOST=0.0.0.0
ENV APP_PORT=8000
ENV OUTPUT_DIR=/app/data

# Çıktılar için dizin
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


