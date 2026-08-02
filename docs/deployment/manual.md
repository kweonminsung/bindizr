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
    $ sudo dpkg -i bindizr_0.1.0_amd64.deb

    # Verify installation
    $ bindizr
    ```

=== "Red Hat Packages (RPM)"

    ```bash
    # Install the .rpm package
    $ sudo rpm -i bindizr_0.1.0_amd64.rpm

    # Verify installation
    $ bindizr
    ```

## 3. Configure BIND as secondary with catalog zone

### Recommended: automated setup script

This script automatically detects your BIND configuration directory and
configures BIND to use Bindizr's catalog zone for automatic zone discovery.

```bash
# Download and run the setup script (defaults to bindizr DNS at 127.0.0.1 port 53)
$ wget -qO- https://raw.githubusercontent.com/kweonminsung/bindizr/main/packaging/scripts/setup_bind.sh | sudo bash

# Or pass the bindizr DNS host and port when bindizr runs elsewhere
$ wget -qO- https://raw.githubusercontent.com/kweonminsung/bindizr/main/packaging/scripts/setup_bind.sh | sudo bash -s -- 10.0.0.5 5353

# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

??? note "Alternative: manual setup"

    First, set variables for your BIND configuration. The paths vary depending
    on your operating system.

    - **For Debian-based systems (e.g., Ubuntu):**
      ```bash
      $ BIND_CONF_FILE=/etc/bind/named.conf
      $ BIND_CACHE_DIR=/var/cache/bind
      ```
    - **For Red Hat-based systems (e.g., Fedora, CentOS):**
      ```bash
      $ BIND_CONF_FILE=/etc/named.conf
      $ BIND_CACHE_DIR=/var/named/slaves
      ```

    Update your main BIND configuration file (`$BIND_CONF_FILE`) by adding the
    following:

    ```bash
    # Configure catalog zone support
    cat <<EOF | sudo tee -a "$BIND_CONF_FILE"
    options {
        allow-notify { any; };
        ixfr-from-differences yes;
        catalog-zones {
            zone "catalog.bind" default-primaries { 127.0.0.1 port 53; };
        };
    };
    EOF

    # Add catalog zone as secondary
    cat <<EOF | sudo tee -a "$BIND_CONF_FILE"
    zone "catalog.bind" {
        type secondary;
        primaries { 127.0.0.1 port 53; };
        file "$BIND_CACHE_DIR/catalog.bind.zone";
        allow-notify { any; };
        ixfr-from-differences yes;
    };
    EOF
    ```

    After saving the changes, restart the BIND service:

    ```bash
    # Restart bind service
    $ sudo systemctl restart bind9  # For Debian-based systems
    $ sudo systemctl restart named  # For Red Hat-based systems
    ```

!!! note

    The `catalog.bind` zone automatically manages all zones created in Bindizr.
    When you create a new zone via the API or CLI, BIND will automatically
    configure it as a secondary zone without requiring manual configuration.

## 4. Configure Bindizr options

Create `/etc/bindizr/bindizr.conf.toml` using the
[Configuration](../configuration.md) reference, adjusting values to match your
environment.

## 5. Start the Bindizr service

```bash
# Start Bindizr service
$ sudo systemctl enable bindizr
$ sudo systemctl start bindizr

# Create an API token for authentication
$ bindizr token create
```

Then confirm the whole path works end to end:

```bash
$ bindizr doctor
```
