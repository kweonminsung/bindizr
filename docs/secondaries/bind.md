# BIND

Catalog zones in the RFC 9432 schema Bindizr serves need **BIND 9.18 or
newer**; Bindizr's interoperability run covers 9.20.

## 1. Register the secondary in Bindizr

Bindizr sends NOTIFY to, and accepts unsigned transfers from, only the
entries of `dns.secondary_addrs`; a BIND missing from it logs
`Transfer status: REFUSED` for every zone. The packaged default,
`127.0.0.1:53`, covers a BIND on the same host. One elsewhere is added by
address or hostname — see [Configuration](../configuration.md#secondaries) —
and the list reloads without a restart:

```toml title="/etc/bindizr/bindizr.conf.toml"
[dns]
secondary_addrs = "10.0.0.14:53"
```

```bash
$ sudo bindizr config reload
```

A [signed transfer](#sign-the-transfers) is authorized by its key, but NOTIFY
still goes only to the list, so a keyed secondary is listed all the same.

## 2. Configure the catalog zone

`catalog-zones` tells BIND to interpret the zone, and `default-primaries` is
where the member zones it names are transferred from. It belongs **inside
the `options { ... }` block that is already there**; the catalog zone itself
is a top-level `zone` statement, appended to the main file. Debian keeps
the two in separate files, Red Hat in one:

=== "Debian (Ubuntu, etc.)"

    Add these inside the `options { ... }` block in `/etc/bind/named.conf.options`:

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

    Add the catalog zone to `/etc/bind/named.conf`:

    ```text
    zone "catalog.bindizr" {
        type secondary;
        primaries { 127.0.0.1 port 5300; };
        file "/var/cache/bind/catalog.bindizr.zone";
        ixfr-from-differences yes;
    };
    ```

    Check the configuration, then restart; a syntax error stops BIND from
    starting:

    ```bash
    $ sudo named-checkconf
    $ sudo systemctl restart bind9
    ```

=== "Red Hat (Fedora, CentOS, etc.)"

    Add these inside the `options { ... }` block in `/etc/named.conf`:

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

    Add the catalog zone to `/etc/named.conf`:

    ```text
    zone "catalog.bindizr" {
        type secondary;
        primaries { 127.0.0.1 port 5300; };
        file "/var/named/slaves/catalog.bindizr.zone";
        ixfr-from-differences yes;
    };
    ```

    Check the configuration, then restart; a syntax error stops BIND from
    starting:

    ```bash
    $ sudo named-checkconf
    $ sudo systemctl restart named
    ```

!!! warning "Do not append a second `options` block"

    BIND accepts only one `options` statement, and `catalog-zones` is only
    valid inside it. Appending a new `options { ... }` to the file makes
    `named-checkconf` fail and BIND refuse to start.

## 3. Check a zone it learned

A package install generates an `rndc` key, so `rndc` answers:

```bash
$ sudo rndc zonestatus example.com
```

A BIND configured from only the statements above, as the chart's and the
Compose example's containers are, has no key, so `rndc` cannot connect. Query
the zone instead, or find its transfer in the log:

```bash
$ dig @127.0.0.1 example.com SOA +norecurse
```

```text
zone example.com/IN: transferred serial 12
```

## Sign the transfers

Create the key in Bindizr, then paste the same name, algorithm, and secret
into BIND. A `server` statement attaches it to every request BIND sends to
that address, which covers the catalog zone and every member zone alike:

```text
key "xfr-key" {
    algorithm hmac-sha256;
    secret "<base64 secret from bindizr tsig-key create --global>";
};

server 10.0.0.5 {
    keys { "xfr-key"; };
};
```

See [TSIG Keys](../cli/tsig-keys.md) for creating the key and granting it the
zones it may transfer.
