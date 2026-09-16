#!/bin/bash
set -e

# Get version from Cargo.toml
VERSION=$(grep '^version =' Cargo.toml | cut -d '"' -f 2)
RELEASE="1"

# TARGET=aarch64-unknown-linux-musl builds the arm64 packages on an arm64 host.
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
case "$TARGET" in
    x86_64-*)  DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
    aarch64-*) DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
    *) echo "Unsupported target: $TARGET (expected x86_64-* or aarch64-*)" >&2; exit 1 ;;
esac

# Point cargo at musl-gcc for the target.
TARGET_ENV="${TARGET//-/_}"
export "CC_${TARGET_ENV}=musl-gcc"
export "CARGO_TARGET_$(printf '%s' "$TARGET_ENV" | tr '[:lower:]' '[:upper:]')_LINKER=musl-gcc"

# Build the static binary
echo "Building static binary..."
cargo build --release --locked --target "$TARGET" -p bindizr

# Create a temporary directory for packaging
echo "Creating temporary packaging directory..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_DIR"' EXIT

# Create directory structure
mkdir -p "$TMP_DIR/usr/bin"
mkdir -p "$TMP_DIR/etc/bindizr"
mkdir -p "$TMP_DIR/usr/lib/systemd/system"
mkdir -p "$TMP_DIR/usr/share/bindizr"
mkdir -p "$TMP_DIR/usr/share/doc/bindizr"
mkdir -p "$TMP_DIR/usr/share/licenses/bindizr"

# Copy files
echo "Copying files..."
install -D -m 755 "target/$TARGET/release/bindizr" "$TMP_DIR/usr/bin/bindizr"
install -p -m 755 packaging/scripts/setup_bind.sh "$TMP_DIR/usr/share/bindizr/setup_bind.sh"
# Keep credentials owner-only in the package; postinstall grants the daemon group access.
install -p -m 600 bindizr.conf.toml "$TMP_DIR/etc/bindizr/bindizr.conf.toml"
install -p -m 644 packaging/bindizr.service "$TMP_DIR/usr/lib/systemd/system/bindizr.service"
install -p -m 644 README.md "$TMP_DIR/usr/share/doc/bindizr/README.md"
install -p -m 644 LICENSE "$TMP_DIR/usr/share/licenses/bindizr/LICENSE"

# Create packages using fpm
echo "Creating packages with fpm..."
fpm -s dir -t deb -n bindizr -v "$VERSION" --iteration "$RELEASE" \
    -a "$DEB_ARCH" -m "Minsung Kweon <kevin136583@gmail.com>" \
    --url "https://github.com/kweonminsung/bindizr" \
    --license "Apache-2.0" \
    --description "DNS Synchronization Service for BIND9" \
    --config-files /etc/bindizr/bindizr.conf.toml \
    --after-install packaging/scripts/postinstall.sh \
    --after-remove packaging/scripts/postremove.sh \
    -C "$TMP_DIR" \
    usr/bin/bindizr usr/lib/systemd/system/bindizr.service etc/bindizr/bindizr.conf.toml usr/share/bindizr/setup_bind.sh usr/share/doc/bindizr/README.md usr/share/licenses/bindizr/LICENSE

fpm -s dir -t rpm -n bindizr -v "$VERSION" --iteration "$RELEASE" \
    -a "$RPM_ARCH" -m "Minsung Kweon <kevin136583@gmail.com>" \
    --url "https://github.com/kweonminsung/bindizr" \
    --license "Apache-2.0" \
    --description "DNS Synchronization Service for BIND9" \
    --config-files /etc/bindizr/bindizr.conf.toml \
    --after-install packaging/scripts/postinstall.sh \
    --after-remove packaging/scripts/postremove.sh \
    -C "$TMP_DIR" \
    usr/bin/bindizr usr/lib/systemd/system/bindizr.service etc/bindizr/bindizr.conf.toml usr/share/bindizr/setup_bind.sh usr/share/doc/bindizr/README.md usr/share/licenses/bindizr/LICENSE

echo "Packages created successfully."
ls -l bindizr*.{deb,rpm}
