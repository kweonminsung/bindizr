#!/bin/sh
set -e

# Create the system user and group for the daemon; Alpine's busybox has no useradd.
if ! getent passwd bindizr >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --user-group --home-dir /var/lib/bindizr \
            --shell /usr/sbin/nologin bindizr
    else
        addgroup -S bindizr
        adduser -S -D -H -h /var/lib/bindizr -s /sbin/nologin -G bindizr bindizr
    fi
fi

# The daemon runs as bindizr; only root and that group may read DB credentials.
if [ -f /etc/bindizr/bindizr.conf.toml ]; then
    chown root:bindizr /etc/bindizr/bindizr.conf.toml
    chmod 0640 /etc/bindizr/bindizr.conf.toml
fi

# Enable the service under whichever init the host runs.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable bindizr.service >/dev/null 2>&1 || true
elif command -v rc-update >/dev/null 2>&1; then
    rc-update add bindizr default >/dev/null 2>&1 || true
fi
