# Knot DNS

Catalog zones need **Knot DNS 3.1 or newer**; Bindizr's interoperability run
covers 3.4.

## Configure the catalog zone

`catalog-role: interpret` makes Knot follow the catalog, and
`catalog-template` names the template every member zone is created from — so
the template, not the catalog zone, carries the primary those zones transfer
from. Add this to `/etc/knot/knot.conf`:

```yaml
remote:
  - id: bindizr
    address: 127.0.0.1@5300

acl:
  - id: notify_from_bindizr
    address: 127.0.0.1
    action: notify

template:
  - id: catalog_member
    master: bindizr
    acl: notify_from_bindizr
    # Serve from the journal so member zones need no zone file on disk.
    zonefile-load: none
    journal-content: all

zone:
  - domain: catalog.bindizr
    master: bindizr
    acl: notify_from_bindizr
    catalog-role: interpret
    catalog-template: catalog_member
```

```bash
$ sudo knotc -c /etc/knot/knot.conf conf-check
$ sudo systemctl restart knot
```

## Check a zone it learned

`zone-status` names the catalog the zone came from, which tells a
catalog-provisioned zone from one configured by hand:

```bash
$ sudo knotc zone-status example.com
[example.com.] role: slave | serial: 12 | catalog: catalog.bindizr. | refresh: +22h59m46s
```

## Sign the transfers

The key goes on the `remote`, so Knot signs both the catalog transfer and
every member transfer the template derives from that remote:

```yaml
key:
  - id: xfr-key
    algorithm: hmac-sha256
    secret: <base64 secret from bindizr tsig-key create --global>
```

Then add `key` to the `bindizr` remote declared above — Knot refuses a repeated
`id` with `duplicate identifier`, so this edits that block rather than adding a
second one, and the address is wherever Bindizr listens:

```yaml
remote:
  - id: bindizr
    address: 10.0.0.5@5300
    key: xfr-key
```

Leave the `acl` matching on address alone: Bindizr sends NOTIFY unsigned, so an
ACL that demanded the key would reject it.

See [TSIG Keys](../cli/tsig-keys.md) for creating the key and granting it the
zones it may transfer.
