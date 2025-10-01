#!/bin/bash
set -e

# Get version from Cargo.toml
VERSION=$(grep '^version =' Cargo.toml | cut -d '"' -f 2)
RELEASE="1"

# Build the static binary
echo "Building static binary..."
cargo build --release --locked --target x86_64-unknown-linux-musl

# Create a temporary directory for packaging
echo "Creating temporary packaging directory..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_DIR"' EXIT

# Create directory structure
mkdir -p "$TMP_DIR/usr/bin"
mkdir -p "$TMP_DIR/etc/bindizr"
mkdir -p "$TMP_DIR/usr/lib/systemd/system"
mkdir -p "$TMP_DIR/usr/share/doc/bindizr"
mkdir -p "$TMP_DIR/usr/share/licenses/bindizr"

# Copy files
echo "Copying files..."
install -D -m 755 target/x86_64-unknown-linux-musl/release/bindizr "$TMP_DIR/usr/bin/bindizr"
install -p -m 644 bindizr.conf.toml "$TMP_DIR/etc/bindizr/bindizr.conf.toml"
install -p -m 644 packaging/bindizr.service "$TMP_DIR/usr/lib/systemd/system/bindizr.service"
install -p -m 644 README.md "$TMP_DIR/usr/share/doc/bindizr/README.md"
install -p -m 644 LICENSE "$TMP_DIR/usr/share/licenses/bindizr/LICENSE"

# Create packages using fpm
echo "Creating packages with fpm..."
fpm -s dir -t deb -n bindizr -v "$VERSION" --iteration "$RELEASE" \
    -a x86_64 -m "Minsung Kweon <kevin136583@gmail.com>" \
    --url "https://github.com/kweonminsung/bindizr" \
    --license "Apache-2.0" \
    --description "DNS Synchronization Service for BIND9" \
    --config-files /etc/bindizr/bindizr.conf.toml \
    --after-install scripts/postinstall.sh \
    --after-remove scripts/postremove.sh \
    -C "$TMP_DIR" \
    usr/bin/bindizr usr/lib/systemd/system/bindizr.service etc/bindizr/bindizr.conf.toml usr/share/doc/bindizr/README.md usr/share/licenses/bindizr/LICENSE

fpm -s dir -t rpm -n bindizr -v "$VERSION" --iteration "$RELEASE" \
    -a x86_64 -m "Minsung Kweon <kevin136583@gmail.com>" \
    --url "https://github.com/kweonminsung/bindizr" \
    --license "Apache-2.0" \
    --description "DNS Synchronization Service for BIND9" \
    --config-files /etc/bindizr/bindizr.conf.toml \
    --after-install scripts/postinstall.sh \
    --after-remove scripts/postremove.sh \
    -C "$TMP_DIR" \
    usr/bin/bindizr usr/lib/systemd/system/bindizr.service etc/bindizr/bindizr.conf.toml usr/share/doc/bindizr/README.md usr/share/licenses/bindizr/LICENSE

echo "Packages created successfully."
ls -l bindizr*.{deb,rpm}
