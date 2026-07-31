#!/bin/bash
set -euo pipefail

if [ -d /etc/bind ]; then
    OPTIONS_FILE="/etc/bind/named.conf.options"
    MAIN_CONF="/etc/bind/named.conf"
    CACHE="/var/cache/bind"
elif [ -d /etc/named ]; then
    OPTIONS_FILE="/etc/named.conf"
    MAIN_CONF="/etc/named.conf"
    CACHE="/var/named/slaves"
else
    echo "BIND not found"
    exit 1
fi

# bindizr's DNS endpoint: setup_bind.sh [host] [port], or BINDIZR_DNS_HOST/BINDIZR_DNS_PORT.
HOST="${1:-${BINDIZR_DNS_HOST:-127.0.0.1}}"
PORT="${2:-${BINDIZR_DNS_PORT:-53}}"

invalid_host() {
    echo "Invalid host: $HOST (expected an IPv4 address)"
    exit 1
}

# BIND primaries entries accept IP literals only.
case "$HOST" in
    '' | *[!0-9.]* | *.*.*.*.* | .* | *. | *..*) invalid_host ;;
    *.*.*.*) ;;
    *) invalid_host ;;
esac
IFS=. read -r o1 o2 o3 o4 <<< "$HOST"
for o in "$o1" "$o2" "$o3" "$o4"; do
    [ "$o" -le 255 ] || invalid_host
done

case "$PORT" in
    '' | *[!0-9]*)
        echo "Invalid port: $PORT"
        exit 1
        ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Invalid port: $PORT (expected 1-65535)"
    exit 1
fi

echo "Configuring BIND for bindizr at $HOST port $PORT"

##################################
# 1. Clean up previous broken syntax
##################################
echo "Cleaning up broken syntax..."

# Remove previously inserted allow-notify, ixfr-from-differences, and catalog-zones;
# host/port match generically so re-runs with a new address replace them.
perl -0777 -pi -e 's/^[ \t]*allow-notify \{ (?:127\.0\.0\.1|any|key "[^"]+"); \};\r?\n//gm' "$OPTIONS_FILE"
perl -0777 -pi -e 's/^[ \t]*ixfr-from-differences yes;\r?\n//gm' "$OPTIONS_FILE"
perl -0777 -pi -e 's/^[ \t]*catalog-zones \{\r?\n[ \t]*zone "catalog\.bind" \{\r?\n[ \t]*default-primaries \{ [^ ;]+ port [0-9]+; \};\r?\n[ \t]*\};\r?\n[ \t]*\};\r?\n//gm' "$OPTIONS_FILE"
perl -0777 -pi -e 's/^[ \t]*catalog-zones \{\r?\n[ \t]*zone "catalog\.bind" default-primaries \{ [^ ;]+ port [0-9]+; \};\r?\n[ \t]*\};\r?\n//gm' "$OPTIONS_FILE"

# Drop only the marker-tagged zone this script wrote; manual blocks are preserved.
perl -0777 -pi -e 's/\r?\n?# managed by bindizr setup_bind\.sh\r?\nzone "catalog\.bind" \{\r?\n(?:[ \t].*\r?\n)*\};\r?\n//gm' "$MAIN_CONF"

##################################
# 2. Insert catalog-zones & allow-notify
##################################
echo "Updating $OPTIONS_FILE..."

awk -v host="$HOST" -v port="$PORT" '
BEGIN {
    depth = 0
    in_options = 0
    added_notify = 0
}
{
    # Check if we are entering the options block
    if ($0 ~ /options[[:space:]]*\{/) {
        in_options = 1
        depth = 1
        print $0
        if (!added_notify) {
            print "    allow-notify { any; };"
            print "    ixfr-from-differences yes;"
            added_notify = 1
        }
        next
    }

    if (in_options) {
        # Track nested braces
        d_open = gsub(/\{/, "{", $0)
        d_close = gsub(/\}/, "}", $0)
        depth += (d_open - d_close)

        # Insert correct catalog-zones syntax before options block closes
        if (depth == 0) {
            print "    catalog-zones {"
            print "        zone \"catalog.bind\" default-primaries { " host " port " port "; };"
            print "    };"
            in_options = 0
        }
    }
    
    print $0
}' "$OPTIONS_FILE" > "$OPTIONS_FILE.tmp"

mv "$OPTIONS_FILE.tmp" "$OPTIONS_FILE"

##################################
# 3. Add catalog zone to MAIN_CONF
##################################
if grep -q 'zone "catalog.bind"' "$MAIN_CONF"; then
    echo "catalog.bind zone already exists in $MAIN_CONF but is not managed by this script;"
    echo "make sure its primaries entry points to $HOST port $PORT."
else
    echo "Adding catalog.bind zone to $MAIN_CONF..."
    cat >> "$MAIN_CONF" <<EOF

# managed by bindizr setup_bind.sh
zone "catalog.bind" {
    type secondary;
    primaries { $HOST port $PORT; };
    file "$CACHE/catalog.bind.zone";
    allow-notify { any; };
    ixfr-from-differences yes;
};
EOF
fi

##################################
# 4. Validate
##################################
echo -e "\nChecking config..."
if named-checkconf; then
    echo "BIND config OK"
else
    echo "BIND config broken."
    exit 1
fi
