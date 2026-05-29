#!/bin/sh
set -eu

CONFIG_PATH="${BINDIZR_CONFIG_PATH:-/etc/bindizr/bindizr.conf.toml}"
DATABASE_TYPE="${BINDIZR_DATABASE_TYPE:-mysql}"
DATABASE_URL="${DATABASE_URL:-}"
SQLITE_FILE_PATH="${BINDIZR_SQLITE_FILE_PATH:-/var/lib/bindizr/bindizr.db}"

mysql_url=""
postgresql_url=""

case "$DATABASE_TYPE" in
  mysql)
    mysql_url="$DATABASE_URL"
    if [ -z "$mysql_url" ]; then
      echo "DATABASE_URL is required when BINDIZR_DATABASE_TYPE=mysql" >&2
      exit 1
    fi
    ;;
  postgresql)
    postgresql_url="$DATABASE_URL"
    if [ -z "$postgresql_url" ]; then
      echo "DATABASE_URL is required when BINDIZR_DATABASE_TYPE=postgresql" >&2
      exit 1
    fi
    ;;
  sqlite)
    ;;
  *)
    echo "Unsupported BINDIZR_DATABASE_TYPE: $DATABASE_TYPE" >&2
    exit 1
    ;;
esac

cat > "$CONFIG_PATH" <<EOF
listen_addr = "${BINDIZR_LISTEN_ADDR:-0.0.0.0}"

[api]
listen_port = ${BINDIZR_API_PORT:-8000}
require_authentication = ${BINDIZR_API_REQUIRE_AUTHENTICATION:-true}

[database]
type = "$DATABASE_TYPE"

[database.mysql]
server_url = "$mysql_url"

[database.sqlite]
file_path = "$SQLITE_FILE_PATH"

[database.postgresql]
server_url = "$postgresql_url"

[dns]
listen_port = ${BINDIZR_DNS_PORT:-53}
secondary_addrs = "${BINDIZR_SECONDARY_ADDRS:-}"
nsupdate_tsig_key = "${BINDIZR_NSUPDATE_TSIG_KEY:-}"

[logging]
log_level = "${BINDIZR_LOG_LEVEL:-info}"
EOF

exec "$@"
