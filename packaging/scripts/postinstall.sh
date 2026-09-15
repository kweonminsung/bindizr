#!/bin/sh
set -e

# Create the system user and group for the daemon.
if ! getent passwd bindizr >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/bindizr \
        --shell /usr/sbin/nologin bindizr
fi

# The daemon runs as bindizr; only root and that group may read DB credentials.
if [ -f /etc/bindizr/bindizr.conf.toml ]; then
    chown root:bindizr /etc/bindizr/bindizr.conf.toml
    chmod 0640 /etc/bindizr/bindizr.conf.toml
fi

# Reload systemd and enable the service.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable bindizr.service >/dev/null 2>&1 || true
fi
