#!/bin/bash
# Falcon MAG — Backend startup with Xvfb + VNC
# ADDED 2026-09-18
set -e

# --- 1. Start Xvfb (virtual display) ---
echo "[startup] Starting Xvfb on :99..."
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!
sleep 2

export DISPLAY=:99

# --- 2. Start fluxbox (window manager) ---
echo "[startup] Starting fluxbox..."
fluxbox > /dev/null 2>&1 &
sleep 1

# --- 3. Start x11vnc (VNC server on :5900) ---
echo "[startup] Starting x11vnc on :5900..."
x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -quiet > /dev/null 2>&1 &
sleep 1

# --- 4. Start noVNC (websockify on :6080) ---
if [ -d /usr/share/novnc ]; then
    echo "[startup] Starting noVNC on :6080..."
    websockify --web /usr/share/novnc 6080 localhost:5900 > /dev/null 2>&1 &
fi

echo "[startup] X11 stack ready. DISPLAY=$DISPLAY"
echo "[startup] VNC: localhost:5900 | noVNC: http://localhost:6080/vnc.html"
echo "[startup] Starting uvicorn..."

# --- 5. Start uvicorn in foreground ---
exec uvicorn main:app --host 0.0.0.0 --port 8888