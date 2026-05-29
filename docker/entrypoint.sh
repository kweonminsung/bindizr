#!/bin/sh
set -eu

CONFIG_PATH="${BINDIZR_CONFIG_PATH:-/etc/bindizr/bindizr.conf.toml}"

cat > "$CONFIG_PATH" <<'EOF'
listen_addr = "0.0.0.0"

[api]
listen_port = 8000
require_authentication = true

[database]
type = "mysql"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "/var/lib/bindizr/bindizr.db"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = ""
nsupdate_tsig_key = ""

[logging]
log_level = "info"
EOF

exec "$@"
