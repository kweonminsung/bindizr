#!/bin/sh
set -e

# Reload systemd, enable the service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable bindizr.service >/dev/null 2>&1 || true
fi
