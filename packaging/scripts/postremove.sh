#!/bin/sh
set -e

# Stop and disable the service under whichever init the host runs.
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop bindizr.service >/dev/null 2>&1 || true
    systemctl disable bindizr.service >/dev/null 2>&1 || true
    systemctl daemon-reload
elif command -v rc-service >/dev/null 2>&1; then
    rc-service bindizr stop >/dev/null 2>&1 || true
    rc-update del bindizr default >/dev/null 2>&1 || true
fi
