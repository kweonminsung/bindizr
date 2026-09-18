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
    # Install using dpkg (bindizr_*_arm64.deb on arm64)
    $ sudo dpkg -i bindizr_*_amd64.deb

    # Verify installation
    $ bindizr
    ```

=== "Red Hat Packages (RPM)"

    ```bash
    # Install the .rpm package (bindizr-*.aarch64.rpm on arm64)
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

The package installs the script at `/usr/share/bindizr/setup_bind.sh`. It
finds the BIND configuration and points it at Bindizr's catalog zone; rerun it
after changing the host or port.

```bash
# Defaults to bindizr DNS at 127.0.0.1 port 5300, where the package configuration listens
$ sudo /usr/share/bindizr/setup_bind.sh

# Or pass the bindizr DNS host and port when bindizr runs elsewhere
$ sudo /usr/share/bindizr/setup_bind.sh 10.0.0.5 5300

# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

Without the package, the same script is
[`packaging/scripts/setup_bind.sh`](https://github.com/kweonminsung/bindizr/blob/main/packaging/scripts/setup_bind.sh)
in the repository.

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
        zone "catalog.bind" default-primaries { 127.0.0.1 port 5300; };
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
    primaries { 127.0.0.1 port 5300; };
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

!!! tip "Signing the transfers"

    The setup above authorizes the secondary by address, which is all a
    loopback pair needs. Where the secondary is elsewhere, name a TSIG key on
    each `primaries` line and paste the same key into BIND — see
    [TSIG Keys](../cli/tsig-keys.md#signing-zone-transfers). Bindizr then
    answers under that key instead of trusting the source address.

## 4. Configure Bindizr options

The package installs `/etc/bindizr/bindizr.conf.toml` ready to run: SQLite at
`/var/lib/bindizr/bindizr.db` (the file and its directory are created on the
first start) and zone transfers on port 5300, leaving 53 to BIND. For MySQL or PostgreSQL, set
`database.type` and that backend's `url`; see [Configuration](../configuration.md)
for every option. The file is `0640 root:bindizr` because it carries database
credentials and the service reads it as the `bindizr` user.

## 5. Start the Bindizr service

```bash
# Start Bindizr service (the package already enabled it at boot)
$ sudo systemctl start bindizr

# Create an admin API token for authentication. The control socket belongs to
# the service user and is owner-only, so the CLI needs sudo.
$ sudo bindizr token create admin --global
```

Then confirm the whole path works end to end:

```bash
$ sudo bindizr doctor
```

A failing line names the piece; [Troubleshooting](../troubleshooting.md) has
the fix for the common ones.

## 6. Create a zone and query it

```bash
$ sudo bindizr zone create example.com --mname ns1.example.com --rname admin@example.com

# The apex NS records are yours to write; BIND will not load a zone without them.
$ sudo bindizr record create example.com @ --type NS --value ns1.example.com
$ sudo bindizr record create example.com www --type A --value 192.0.2.1

# BIND learned the zone through the catalog and pulled it; it answers on 53
$ dig @127.0.0.1 www.example.com A +short
192.0.2.1

# Which serial each secondary serves, against Bindizr's
$ sudo bindizr zone status example.com
```

The package also installs shell completions and `man bindizr`, so the command
surface is reachable without the docs.

From here the [CLI](../cli/index.md) and the [HTTP API](../http-api/index.md)
cover the rest. To move zones from a nameserver you already run, see
[Migrating an Existing Primary](migrating.md).
