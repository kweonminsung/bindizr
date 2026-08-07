# Manual Installation

For package-based installation on a VM or bare-metal host. This installs BIND9,
installs the Bindizr binary or package, configures BIND9 as a secondary using
the catalog zone, and starts Bindizr as a system service.

## 1. Install BIND9

=== "Debian (Ubuntu, etc.)"

    ```bash
    $ sudo apt-get update
    $ sudo apt-get install sudo ufw dnsutils bind9
    ```

=== "Red Hat (Fedora, CentOS, etc.)"

    ```bash
    $ sudo yum install bind bind-utils
    ```

## 2. Download Bindizr and install

You can download the latest bindizr binary from
[Release](https://github.com/kweonminsung/bindizr/releases/latest).

For building from source, see the
[packaging documentation](https://github.com/kweonminsung/bindizr/blob/main/packaging/README.md).

=== "Debian Packages (DPKG)"

    ```bash
    # Install using dpkg
    $ sudo dpkg -i bindizr_*_amd64.deb

    # Verify installation
    $ bindizr
    ```

=== "Red Hat Packages (RPM)"

    ```bash
    # Install the .rpm package
    $ sudo rpm -i bindizr-*.x86_64.rpm

    # Verify installation
    $ bindizr
    ```

## 3. Configure BIND as secondary with catalog zone

The `catalog.bind` zone is what makes this hands-off from here on: when you
create or delete a zone via the API or CLI, BIND picks it up as a secondary
without any further configuration.

Two things have to be in place — `catalog-zones` inside BIND's global `options`,
and `catalog.bind` itself declared as a secondary zone. The setup script does
both; the manual steps below do the same thing by hand.

### Recommended: automated setup script

This script automatically detects your BIND configuration directory and
configures BIND to use Bindizr's catalog zone for automatic zone discovery.

```bash
$ SETUP_URL=https://raw.githubusercontent.com/kweonminsung/bindizr/main/packaging/scripts/setup_bind.sh

# Defaults to bindizr DNS at 127.0.0.1 port 53
$ wget -qO- "$SETUP_URL" | sudo bash

# Or pass the bindizr DNS host and port when bindizr runs elsewhere
$ wget -qO- "$SETUP_URL" | sudo bash -s -- 10.0.0.5 5353

# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

### Alternative: manual setup

Two files are involved, and on Debian they are not the same file. Set the paths
for your system first:

=== "Debian (Ubuntu, etc.)"

    ```bash
    $ BIND_OPTIONS_FILE=/etc/bind/named.conf.options
    $ BIND_MAIN_CONF=/etc/bind/named.conf
    $ BIND_CACHE_DIR=/var/cache/bind
    ```

=== "Red Hat (Fedora, CentOS, etc.)"

    ```bash
    $ BIND_OPTIONS_FILE=/etc/named.conf
    $ BIND_MAIN_CONF=/etc/named.conf
    $ BIND_CACHE_DIR=/var/named/slaves
    ```

Open `$BIND_OPTIONS_FILE` in an editor and add these three directives **inside
the `options { ... }` block that is already there**:

```text
options {
    // ... whatever your system already has ...

    allow-notify { any; };
    ixfr-from-differences yes;
    catalog-zones {
        zone "catalog.bind" default-primaries { 127.0.0.1 port 53; };
    };
};
```

!!! warning "Do not append a second `options` block"

    BIND accepts only one `options` statement, and `catalog-zones` is only valid
    inside it. Appending a new `options { ... }` to the file makes
    `named-checkconf` fail and BIND refuse to start.

The catalog zone itself is a top-level `zone` statement, so it can be appended
to the main configuration file:

```bash
cat <<EOF | sudo tee -a "$BIND_MAIN_CONF"

zone "catalog.bind" {
    type secondary;
    primaries { 127.0.0.1 port 53; };
    file "$BIND_CACHE_DIR/catalog.bind.zone";
    allow-notify { any; };
    ixfr-from-differences yes;
};
EOF
```

Check the configuration before restarting, since a syntax error here stops BIND
from starting:

```bash
$ sudo named-checkconf
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

## 4. Configure Bindizr options

Create `/etc/bindizr/bindizr.conf.toml` using the
[Configuration](../configuration.md) reference, adjusting values to match your
environment.

## 5. Start the Bindizr service

```bash
# Start Bindizr service
$ sudo systemctl enable bindizr
$ sudo systemctl start bindizr

# Create an admin API token for authentication
$ bindizr token create --name admin --global
```

Then confirm the whole path works end to end:

```bash
$ bindizr doctor
```
