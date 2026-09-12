#!/bin/sh
set -e

# The config carries database credentials and the service is no longer root,
# so only the daemon's group may read it.
if ! getent passwd bindizr >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/bindizr \
        --shell /usr/sbin/nologin bindizr
fi

if [ -f /etc/bindizr/bindizr.conf.toml ]; then
    chown root:bindizr /etc/bindizr/bindizr.conf.toml
    chmod 0640 /etc/bindizr/bindizr.conf.toml
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable bindizr.service >/dev/null 2>&1 || true
fi
