# Manual Installation

For package-based installation on a VM or bare-metal host. This installs a
name server, installs the Bindizr binary or package, configures that server as
a secondary using the catalog zone, and starts Bindizr as a system service.

## 1. Install a name server

Bindizr drives the secondary over standard AXFR, IXFR, NOTIFY and catalog
zones, so any server in [Secondary Servers](../secondaries/index.md) will do.
BIND is what the rest of this page installs.

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

## 3. Configure the secondary

The `catalog.bindizr` zone is what makes this hands-off from here on: create or
delete a zone via the API or CLI and the secondary picks it up, with no
configuration of its own. It is an ordinary RFC 9432 catalog zone, so the
secondary does not have to be BIND.

Follow the page for the server you installed in step 1, using Bindizr's
packaged defaults — DNS on `127.0.0.1` port 5300, leaving 53 to the secondary:

- [BIND](../secondaries/bind.md)
- [Knot DNS](../secondaries/knot.md)
- [NSD](../secondaries/nsd.md)
- [PowerDNS](../secondaries/powerdns.md)

[Secondary Servers](../secondaries/index.md) covers what the setup has in
common, signing the transfers with TSIG, and which versions support catalog
zones.

## 4. Configure Bindizr options

The package installs `/etc/bindizr/bindizr.conf.toml` ready to run: SQLite at
`/var/lib/bindizr/bindizr.db` (the file and its directory are created on the
first start) and zone transfers on port 5300, leaving 53 to the secondary. For MySQL or PostgreSQL, set
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

# The apex NS records are yours to write; a secondary will not load a zone without them.
$ sudo bindizr record create example.com @ --type NS --value ns1.example.com
$ sudo bindizr record create example.com www --type A --value 192.0.2.1

# The secondary learned the zone through the catalog and pulled it; it answers on 53
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
