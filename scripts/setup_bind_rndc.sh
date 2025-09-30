#!/bin/bash
set -euo pipefail

# 1. Detect BIND configuration directory depending on OS type
if [ -d /etc/bind ]; then
    BIND_CONF_DIR="/etc/bind"
elif [ -d /etc/named ]; then
    BIND_CONF_DIR="/etc/named"
else
    echo "❌ Could not determine BIND config directory."
    exit 1
fi

CONF_FILE="$BIND_CONF_DIR/named.conf"
RNDC_KEY_FILE="$BIND_CONF_DIR/rndc.key"
BINDIZR_FILE="$BIND_CONF_DIR/bindizr/named.conf.bindizr"

echo "✅ Using BIND_CONF_DIR=$BIND_CONF_DIR"

# 2. Generate RNDC key (skip if already exists)
if [ ! -f "$RNDC_KEY_FILE" ]; then
    echo "🔑 Generating RNDC key..."
    rndc-confgen -a -c "$RNDC_KEY_FILE"
else
    echo "ℹ️ RNDC key already exists at $RNDC_KEY_FILE (skipping)"
fi

# 3. Append include statements if not already present
LINES=(
  "include \"$BINDIZR_FILE\";"
  "include \"$RNDC_KEY_FILE\";"
)

for line in "${LINES[@]}"; do
  if ! grep -qxF "$line" "$CONF_FILE"; then
    echo "$line" | sudo tee -a "$CONF_FILE" >/dev/null
    echo "➕ Added: $line"
  else
    echo "✔ Already present: $line"
  fi
done

# 4. Add controls block if not already present
if ! grep -q "controls {" "$CONF_FILE"; then
    cat <<EOF | sudo tee -a "$CONF_FILE" >/dev/null
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
echo "   sudo systemctl restart named"
