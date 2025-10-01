#!/bin/bash
set -euo pipefail

# 1. Detect OS Family
if [ -d /etc/bind ]; then
    OS_FAMILY="debian"
elif [ -d /etc/named ]; then
    OS_FAMILY="redhat"
else
    echo "❌ Could not determine BIND config directory. Neither /etc/bind nor /etc/named found."
    exit 1
fi

# 2. Set OS-specific variables
if [ "$OS_FAMILY" = "debian" ]; then
    BIND_CONF_FILE="/etc/bind/named.conf"
    RNDC_KEY_FILE="/etc/bind/rndc.key"
elif [ "$OS_FAMILY" = "redhat" ]; then
    BIND_CONF_FILE="/etc/named.conf"
    RNDC_KEY_FILE="/etc/rndc.key"
fi
BINDIZR_DIR="/etc/bindizr"
ZONE_CONFIG_DIR="$BINDIZR_DIR/zones"
ZONE_CONFIG_FILE="$BINDIZR_DIR/zones/named.conf"

# 3. Create bindizr config directory if it doesn't exist
if [ ! -d "$ZONE_CONFIG_DIR" ]; then
    echo "📁 Creating bindizr config directory at $BINDIZR_DIR..."
    sudo mkdir -p "$ZONE_CONFIG_DIR"
fi

# 4. Create zone config file if it doesn't exist
if [ ! -f "$ZONE_CONFIG_FILE" ]; then
    echo "📄 Creating zone config file at $ZONE_CONFIG_FILE..."
    sudo touch "$ZONE_CONFIG_FILE"
fi

# 5. Generate RNDC key and set permissions
if [ ! -f "$RNDC_KEY_FILE" ]; then
    echo "🔑 Generating RNDC key..."
    sudo rndc-confgen -a -c "$RNDC_KEY_FILE"

    echo "🔒 Setting permissions for $RNDC_KEY_FILE..."
    if [ "$OS_FAMILY" = "debian" ]; then
        sudo chown root:bind "$RNDC_KEY_FILE"
    elif [ "$OS_FAMILY" = "redhat" ]; then
        sudo chown root:named "$RNDC_KEY_FILE"
    fi
    sudo chmod 640 "$RNDC_KEY_FILE"
else
    echo "ℹ️ RNDC key already exists at $RNDC_KEY_FILE (skipping)"
fi

# 6. Append include statements if not already present
LINES=(
  "include \"$ZONE_CONFIG_FILE\";"
  "include \"$RNDC_KEY_FILE\";"
)

for line in "${LINES[@]}"; do
  if ! grep -qxF "$line" "$BIND_CONF_FILE"; then
    echo "$line" | sudo tee -a "$BIND_CONF_FILE" >/dev/null
    echo "➕ Added: $line"
  else
    echo "✔ Already present: $line"
  fi
done

# 7. Add controls block if not already present
if ! grep -q "controls {" "$BIND_CONF_FILE"; then
    cat <<EOF | sudo tee -a "$BIND_CONF_FILE" >/dev/null
controls {
    inet 127.0.0.1 port 953
        allow { 127.0.0.1; } keys { "rndc-key"; };
};
EOF
    echo "➕ Added default controls block (localhost only)"
else
    echo "✔ controls block already exists (not modified)"
fi

echo "✅ Setup complete. Restart named to apply changes:"
if [ "$OS_FAMILY" = "debian" ]; then
    echo "   sudo systemctl restart bind9"
elif [ "$OS_FAMILY" = "redhat" ]; then
    echo "   sudo systemctl restart named"
fi
