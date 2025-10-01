#!/bin/sh
set -e

# Stop and disable the service, reload systemd
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop bindizr.service >/dev/null 2>&1 || true
    systemctl disable bindizr.service >/dev/null 2>&1 || true
    systemctl daemon-reload
fi
