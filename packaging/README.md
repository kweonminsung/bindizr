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

### 2. Rust Toolchain

You'll also need the Rust compiler, Cargo, and `musl-tools` for static linking.

*   **On Debian/Ubuntu:**
    ```bash
    sudo apt install -y rustc cargo musl-tools
    ```
*   **On Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y rust cargo musl-tools
    ```

## Package Contents

The packages carry the `bindizr` daemon only: the binary, its systemd unit,
and `/etc/bindizr/bindizr.conf.toml`.

The `bindizr-external-dns` adapter is deliberately left out. ExternalDNS is a
Kubernetes controller and every deployment layout bindizr documents runs the
adapter inside the cluster, keeping the unauthenticated external-dns→adapter
hop on the pod loopback or a `ClusterIP`. Running it on a systemd host would
push that hop across the network. It ships in the container image instead.

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

## Installing the Package

### Debian/Ubuntu

```bash
$ sudo dpkg -i bindizr_*.deb
```

### Fedora/CentOS/RHEL

```bash
$ sudo rpm -i bindizr_*.rpm
