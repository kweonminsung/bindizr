# Manual Installation

Install Bindizr and a BIND secondary on the same Linux host, then create and
query a zone. The package uses SQLite and a systemd service by default.

## 1. Install a name server

Bindizr drives the secondary over standard AXFR, IXFR, NOTIFY and catalog
zones, so any server in [Secondary Servers](../secondaries/index.md) will do.
BIND is what the rest of this page installs.

=== "Debian (Ubuntu, etc.)"

    ```bash
    sudo apt-get update
    sudo apt-get install dnsutils bind9
    ```

=== "Red Hat (Fedora, CentOS, etc.)"

    ```bash
    sudo yum install bind bind-utils
    ```

## 2. Download Bindizr and install

You can download the latest Bindizr binary from
[Release](https://github.com/kweonminsung/bindizr/releases/latest). Each
release also carries `THIRD_PARTY_LICENSES.html`, the licenses of the crates
the binaries are built from.

To build the binary yourself instead, see [Building from Source](source.md).

=== "Debian Packages (DPKG)"

    ```bash
    # Install using dpkg (bindizr_*_arm64.deb on arm64)
    sudo dpkg -i bindizr_*_amd64.deb

    # Verify installation
    bindizr --version
    ```

=== "Red Hat Packages (RPM)"

    ```bash
    # Install the .rpm package (bindizr-*.aarch64.rpm on arm64)
    sudo rpm -i bindizr-*.x86_64.rpm

    # Verify installation
    bindizr --version
    ```

## 3. Configure Bindizr

The package installs `/etc/bindizr/bindizr.conf.toml` ready to run: SQLite at
`/var/lib/bindizr/bindizr.db` and DNS on `127.0.0.1:5300`, leaving port 53
to the secondary. For MySQL or PostgreSQL, set `database.type` and that
backend's `url`; see [Configuration](../configuration.md).

The service reads the configuration as the `bindizr` user. Keep its installed
ownership and permissions (`0640 root:bindizr`) when editing it.

## 4. Start Bindizr

```bash
# Start Bindizr service (the package already enabled it at boot)
sudo systemctl start bindizr

# Create and save an admin API token; its secret is shown once.
sudo bindizr token create admin --role admin
```

Use `sudo` for CLI commands on a package install: they require the daemon's
user or root.

## 5. Configure the secondary

Follow the [BIND setup](../secondaries/bind.md) to register the secondary
and configure its catalog zone. Its example uses the same local ports as this
guide. For another server, follow [Knot DNS](../secondaries/knot.md),
[NSD](../secondaries/nsd.md), or [PowerDNS](../secondaries/powerdns.md).

After restarting the secondary, check the installation:

```bash
sudo bindizr doctor
```

A failing line names the piece; [Troubleshooting](../troubleshooting.md) has
the fix for the common ones.

## 6. Create a zone and query it

```bash
# The zone starts with an apex NS record naming ns1.example.com, which a
# secondary needs before it will load the zone; --no-apex-ns leaves that to you.
sudo bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
sudo bindizr record create example.com www --type A --value 192.0.2.1

# The secondary learned the zone through the catalog and pulled it; it answers on 53
dig @127.0.0.1 www.example.com A +short
# Expected answer: 192.0.2.1

# Which serial each secondary serves, against Bindizr's
sudo bindizr zone status example.com
```

The package also installs shell completions and `man bindizr`, so the command
surface is reachable without the docs.

From here the [CLI](../cli/index.md) and the [HTTP API](../http-api/index.md)
cover the rest. To move zones from a name server you already run, see
[Migrating an Existing Primary](migrating.md).
