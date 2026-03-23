#!/bin/bash
set -euo pipefail

if [ -d /etc/bind ]; then
    OS="debian"
    OPTIONS_FILE="/etc/bind/named.conf.options"
    MAIN_CONF="/etc/bind/named.conf"
    CACHE="/var/cache/bind"
elif [ -d /etc/named ]; then
    OS="redhat"
    OPTIONS_FILE="/etc/named.conf"
    MAIN_CONF="/etc/named.conf"
    CACHE="/var/named/slaves"
else
    echo "BIND not found"
    exit 1
fi

HOST="127.0.0.1"
PORT="53"

##################################
# 1. Clean up previous broken syntax
##################################
echo "Cleaning up broken syntax..."

# Remove previously inserted allow-notify and broken catalog-zones
perl -0777 -pi -e 's/^[ \t]*allow-notify \{ 127\.0\.0\.1; \};\r?\n//gm' "$OPTIONS_FILE"
perl -0777 -pi -e 's/^[ \t]*catalog-zones \{\r?\n[ \t]*zone "catalog\.bind" \{\r?\n[ \t]*default-primaries \{ 127\.0\.0\.1 port 5353; \};\r?\n[ \t]*\};\r?\n[ \t]*\};\r?\n//gm' "$OPTIONS_FILE"

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
            print "    allow-notify { " host "; };"
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
    echo "catalog.bind zone already exists in $MAIN_CONF"
else
    echo "Adding catalog.bind zone to $MAIN_CONF..."
    cat >> "$MAIN_CONF" <<EOF

zone "catalog.bind" {
    type secondary;
    primaries { $HOST port $PORT; };
    file "$CACHE/catalog.bind.zone";
    allow-notify { $HOST; };
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