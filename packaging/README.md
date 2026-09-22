# Packaging Bindizr

This document provides instructions for building Debian and RPM packages for Bindizr from the source code using `fpm`.

## Prerequisites

This section describes how to install the necessary dependencies to build the packages.

### 1. FPM (Effing Package Management)

`fpm` is a Ruby-based tool, so it's best installed via RubyGems.

**Install Ruby and Build Tools**

First, you need to install Ruby and some development tools.

*   **On Debian/Ubuntu:**
    ```bash
    sudo apt update
    sudo apt install -y ruby ruby-dev build-essential
    ```
*   **On Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y ruby ruby-devel gcc make rpm-build
    ```

**Install fpm**

Now, install `fpm` using `gem`:
```bash
sudo gem install --no-document fpm
```

You can verify the installation by checking the version:
```bash
fpm --version
```

### 2. Rust Toolchain and musl

Install Rust with [rustup](https://rustup.rs/) — Debian and Ubuntu package a
compiler older than the 1.94 the workspace requires — and the musl C compiler
the static build links with. That target has no system OpenSSL, so the build
compiles its own, which needs perl and make.

*   **On Debian/Ubuntu** (perl and make come with `build-essential` above):
    ```bash
    sudo apt install -y musl-tools
    ```
*   **On Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y musl-gcc make perl-core
    ```

Then add the target the script builds for:
```bash
rustup target add x86_64-unknown-linux-musl    # aarch64-unknown-linux-musl on arm64
```

[Building from Source](https://kweonminsung.github.io/bindizr/deployment/source/)
covers the toolchain and the dynamic build in more detail.

## Building Packages

A helper script is provided to build both `.deb` and `.rpm` packages.

```bash
# Clone the repository
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr

# Run the build script
$ ./packaging/scripts/build_packages.sh

# The generated packages will be in the root directory
$ ls bindizr*.{deb,rpm}
```

The script builds `x86_64-unknown-linux-musl` by default. On an arm64 host,
name the target to build the arm64 packages, as the release workflow does:

```bash
$ TARGET=aarch64-unknown-linux-musl ./packaging/scripts/build_packages.sh
```

## Building the Container Image

`build_image.sh` builds the image for amd64 and arm64 as one manifest and
pushes it. The argument is the tag (default: the Cargo version); `IMAGE`
overrides the repository.

```bash
$ ./packaging/scripts/build_image.sh
```

## Installing the Package

### Debian/Ubuntu

```bash
$ sudo dpkg -i bindizr_*.deb
```

### Fedora/CentOS/RHEL

```bash
$ sudo rpm -i bindizr_*.rpm
