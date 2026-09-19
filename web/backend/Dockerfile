# ============================================================
# Falcon MAG — Backend + Framework CLI + Xvfb/VNC + External Tools
# ============================================================
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DISPLAY=:99 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# --- System dependencies (with exploitdb, nmap, testssl deps) ---
RUN apt-get update -o Acquire::Retries=5 && \
    apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev curl ca-certificates \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libdbus-1-3 libxcb1 libxkbcommon0 \
        libatspi2.0-0 libx11-6 libxcomposite1 libxdamage1 \
        libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
        libcairo2 libasound2 fonts-liberation fonts-noto-color-emoji \
        xvfb x11vnc fluxbox \
        novnc websockify \
        fonts-dejavu fonts-noto \
                nmap openssl dnsutils git bash procps unzip \
    && rm -rf /var/lib/apt/lists/*

# --- searchsploit (exploitdb) — installed via git (not in Debian Trixie repos) ---
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && chmod +x /opt/exploitdb/searchsploit

# --- Python dependencies ---
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# --- Playwright Chromium ---
RUN playwright install --with-deps chromium

# --- testssl.sh (TLS scanner) ---
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /opt/testssl/testssl.sh

# --- subfinder (projectdiscovery — pre-built Go binary) ---
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
        amd64) SUBF_ARCH=amd64 ;; \
        arm64) SUBF_ARCH=arm64 ;; \
        *) SUBF_ARCH=amd64 ;; \
    esac \
    && curl -fsSL --retry 5 --retry-delay 3 \
        "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${SUBF_ARCH}.zip" \
        -o /tmp/sf.zip \
    && unzip -q /tmp/sf.zip -d /tmp/sf/ \
    && mv /tmp/sf/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/sf /tmp/sf.zip

# --- Application code ---
COPY . /app/

# --- Runtime dirs ---
RUN mkdir -p /app/data /app/reports /app/exports \
    /app/bug_bounty_reports /app/framework/profiles /app/framework/output

# --- Startup script (fix CRLF from Windows) ---
COPY start-with-vnc.sh /start-with-vnc.sh
RUN sed -i 's/\r$//' /start-with-vnc.sh && chmod +x /start-with-vnc.sh

EXPOSE 8888 5900 6080

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:8888/api/health || exit 1

CMD ["/start-with-vnc.sh"]