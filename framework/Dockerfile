# ============================================================
# Falcon MAG Framework - Docker Image v2
# ============================================================

FROM python:3.12-slim

LABEL maintainer="Falcon MAG"
LABEL description="Security Assessment Framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    openssl \
    bind9-host \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /opt/testssl/testssl.sh

# subfinder
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH=amd64; fi && \
    curl -L "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${ARCH}.zip" -o /tmp/subfinder.zip \
    && cd /tmp && unzip subfinder.zip && mv subfinder /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium && playwright install-deps chromium

COPY . .

RUN mkdir -p /app/output /app/logs

ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]