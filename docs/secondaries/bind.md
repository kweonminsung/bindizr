# BIND

Catalog zones in the RFC 9432 schema Bindizr serves need **BIND 9.18 or
newer**; Bindizr's interoperability run covers 9.20.

## Configure the catalog zone

Two files are involved, and on Debian they are not the same file. Set the
paths for your system first:

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

`catalog-zones` tells BIND to interpret the zone, and `default-primaries` is
where the member zones it names are transferred from. Open `$BIND_OPTIONS_FILE`
and add these directives **inside the `options { ... }` block that is already
there**:

```text
options {
    // ... whatever your system already has ...

    allow-notify { 127.0.0.1; };
    ixfr-from-differences yes;
    catalog-zones {
        zone "catalog.bindizr" default-primaries { 127.0.0.1 port 5300; };
    };
};
```

!!! warning "Do not append a second `options` block"

    BIND accepts only one `options` statement, and `catalog-zones` is only
    valid inside it. Appending a new `options { ... }` to the file makes
    `named-checkconf` fail and BIND refuse to start.

The catalog zone itself is a top-level `zone` statement, so it can be appended
to the main configuration file:

```bash
cat <<EOF | sudo tee -a "$BIND_MAIN_CONF"

zone "catalog.bindizr" {
    type secondary;
    primaries { 127.0.0.1 port 5300; };
    file "$BIND_CACHE_DIR/catalog.bindizr.zone";
    ixfr-from-differences yes;
};
EOF
```

Check the configuration before restarting, since a syntax error here stops
BIND from starting:

```bash
$ sudo named-checkconf
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

## Check a zone it learned

```bash
$ sudo rndc zonestatus example.com
```

## Sign the transfers

Create the key in Bindizr, then paste the same name, algorithm, and secret
into BIND. A `server` statement attaches it to every request BIND sends to
that address, which covers the catalog zone and every member zone alike:

```text
key "xfr-key" {
    algorithm hmac-sha256;
    secret "<base64 secret from bindizr tsig-key create>";
};

server 10.0.0.5 {
    keys { "xfr-key"; };
};
```

See [TSIG Keys](../cli/tsig-keys.md) for creating the key and granting it the
zones it may transfer.
