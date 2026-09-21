#!/bin/sh
# PowerDNS as a Bindizr secondary. A consumer zone is created with pdnsutil
# rather than in a file, so the bootstrap runs here.
set -e
DB=/var/lib/powerdns/pdns.sqlite3
if [ ! -f "$DB" ]; then
  sqlite3 "$DB" < /usr/local/share/doc/pdns/schema.sqlite3.sql
fi
BINDIZR_IP=$(getent hosts bindizr | awk '{print $1; exit}')
pdnsutil create-secondary-zone catalog.bindizr "$BINDIZR_IP" 2>/dev/null || true
pdnsutil set-kind catalog.bindizr consumer
exec pdns_server --disable-syslog --config-dir=/etc/powerdns
