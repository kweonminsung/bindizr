# Building from Source

For a host the packages do not cover, or to run a change before it is
released. The result is the same `bindizr` binary the `.deb` and `.rpm`
carry; once it is built, [Manual Installation](manual.md) covers the
secondary, the configuration, and the service around it.

## 1. Install a Rust toolchain

Bindizr needs Rust 1.94 or newer. Install it with
[rustup](https://rustup.rs/) rather than from the distribution: Debian and
Ubuntu package a compiler older than that in every current release, and
rustup keeps the toolchain current on every platform below.

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ . "$HOME/.cargo/env"
$ rustc --version
```

## 2. Install the build dependencies

A C compiler builds the three native libraries in the dependency tree (the
DNSSEC cryptography, the bundled SQLite, and the TLS stack behind the API),
and the system OpenSSL is linked for the signing backend, located through
pkg-config. Nothing else is needed: no CMake, no bindgen, and no SQLite
package, since that one is built in.

=== "Debian (Ubuntu, etc.)"

    ```bash
    $ sudo apt-get install build-essential pkg-config libssl-dev
    ```

=== "Red Hat (Fedora, CentOS, etc.)"

    ```bash
    $ sudo dnf install gcc pkgconf openssl-devel
    ```

=== "macOS"

    ```bash
    $ xcode-select --install
    $ brew install openssl@3
    ```

    Homebrew's OpenSSL is found at its default prefix, so neither
    pkg-config nor `OPENSSL_DIR` is needed.

## 3. Build

```bash
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr
$ cargo build --release --locked -p bindizr
$ target/release/bindizr --version
```

`--locked` builds the dependency versions `Cargo.lock` pins, the ones the
release packages are built from. `cargo install --path crates/bindizr
--locked` builds and copies the binary into `~/.cargo/bin` in one step.

The [ExternalDNS](../external-dns.md) webhook adapter is a second binary in
the same workspace; add `-p bindizr-external-dns` to build it too.

## 4. Static binary and packages

The release packages carry a statically linked musl binary, so one build
runs on any distribution. That target has no system OpenSSL, so the build
compiles its own, which needs perl and make next to the musl C compiler:

=== "Debian (Ubuntu, etc.)"

    ```bash
    $ sudo apt-get install musl-tools
    ```

    perl and make come with `build-essential` above.

=== "Red Hat (Fedora, CentOS, etc.)"

    ```bash
    $ sudo dnf install musl-gcc make perl-core
    ```

macOS has no musl toolchain of its own; build the static binary on a Linux
host of the target's architecture, as the release workflow does.

```bash
$ rustup target add x86_64-unknown-linux-musl    # aarch64-unknown-linux-musl on arm64
$ CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --locked --target x86_64-unknown-linux-musl -p bindizr
```

`packaging/scripts/build_packages.sh` runs this build and wraps the result
in the `.deb` and `.rpm` together with the systemd unit, the default
configuration, the man page, and the shell completions. Its own
prerequisite, `fpm`, is in the
[packaging README](https://github.com/kweonminsung/bindizr/blob/main/packaging/README.md).

## 5. Install it by hand

Without a package, the pieces it would have put in place are in
`packaging/`:

- `bindizr.service` is the systemd unit. It expects the binary at
  `/usr/bin/bindizr`, a `bindizr` system user, and `/var/lib/bindizr` as the
  state directory.
- `scripts/postinstall.sh` creates that user and makes the configuration
  file `0640 root:bindizr`, since it carries database credentials.
- `bindizr.conf.toml` in the repository root is the configuration the
  packages install; `/etc/bindizr/bindizr.conf.toml` is where the daemon
  looks by default.

```bash
$ sudo install -m 755 target/release/bindizr /usr/bin/bindizr
$ sudo install -D -m 600 bindizr.conf.toml /etc/bindizr/bindizr.conf.toml
$ sudo install -m 644 packaging/bindizr.service /usr/lib/systemd/system/bindizr.service
$ sudo sh packaging/scripts/postinstall.sh
```

The binary generates its own man page and completions, so they cannot drift
from `--help`: `bindizr man` and `bindizr completion bash` (or `zsh`,
`fish`) print them for your host's directories.

From here, continue with [Manual Installation](manual.md#3-configure-the-secondary)
from step 3: the secondary, the configuration, and the first start.
