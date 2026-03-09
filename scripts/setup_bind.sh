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
PORT="5353"

##################################
# Insert catalog-zones safely
##################################

if grep -q "catalog-zones" "$OPTIONS_FILE"; then
    echo "catalog-zones already exists"
else
    echo "Adding catalog-zones"

awk -v host="$HOST" -v port="$PORT" '
BEGIN{
    depth=0
    in_options=0
}

{
    print

    if ($0 ~ /options[[:space:]]*{/) {
        in_options=1
        depth=1
        next
    }

    if (in_options) {
        if ($0 ~ /{/) depth++
        if ($0 ~ /}/) depth--

        if (depth==0) {
            print "    catalog-zones {"
            print "        zone \"catalog.bind\" {"
            print "            default-primaries { "host" port "port"; };"
            print "        };"
            print "    };"
            in_options=0
        }
    }
}
' "$OPTIONS_FILE" > "$OPTIONS_FILE.tmp"

mv "$OPTIONS_FILE.tmp" "$OPTIONS_FILE"
fi

##################################
# Add catalog zone
##################################

if grep -q 'zone "catalog.bind"' "$MAIN_CONF"; then
    echo "catalog.bind zone already exists"
else
    cat >> "$MAIN_CONF" <<EOF

zone "catalog.bind" {
    type secondary;
    primaries { $HOST port $PORT; };
    file "$CACHE/catalog.bind.zone";
};
EOF
fi

##################################
# Validate
##################################

echo
echo "Checking config..."

if named-checkconf; then
    echo "BIND config OK"
else
    echo "BIND config broken"
    exit 1
fi