#!/bin/sh
# Build the Alpine package with abuild, inside an Alpine container that
# build_packages.sh starts: /stage holds the packaged tree, /packaging this
# directory's parent, /out the repository root the .apk lands in.
# Usage: build_apk.sh <apk version> <release> <cargo version>
set -e
APK_VERSION="$1"
RELEASE="$2"

apk add -q alpine-sdk

# abuild wants the APKBUILD in <repo>/<pkgname>; the scripts sit beside it.
mkdir -p /build/pkg/bindizr
sed -e "s/^pkgver=.*/pkgver=$APK_VERSION/" -e "s/^pkgrel=.*/pkgrel=$RELEASE/" \
    /packaging/alpine/APKBUILD > /build/pkg/bindizr/APKBUILD
cp /packaging/scripts/postinstall.sh /build/pkg/bindizr/bindizr.post-install
cp /packaging/scripts/postremove.sh /build/pkg/bindizr/bindizr.pre-deinstall
cd /build/pkg/bindizr

# abuild signs with a key it must also trust; this one lives only in the
# container, so the package installs with --allow-untrusted.
abuild-keygen -a -n -q
cp "$HOME"/.abuild/*.rsa.pub /etc/apk/keys/
STAGE=/stage abuild -F -r -P /build/out

# Use the Cargo version in the release asset when the native version has a
# hex field, whose tilde may be renamed by the release host.
ARCH=$(apk --print-arch)
case "$APK_VERSION" in
    *~*) ASSET_VERSION="$3" ;;
    *) ASSET_VERSION="$APK_VERSION" ;;
esac
cp /build/out/pkg/"$ARCH"/bindizr-"$APK_VERSION"-r"$RELEASE".apk \
    /out/bindizr-"$ASSET_VERSION"-r"$RELEASE"."$ARCH".apk
