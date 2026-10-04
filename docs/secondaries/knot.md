# Knot DNS

Catalog zones need **Knot DNS 3.1 or newer**; Bindizr's interoperability run
covers 3.4.

## 1. Register the secondary in Bindizr

Register the secondary's address so it receives NOTIFY and can transfer
zones. This example uses a server on the same host, listening on port 53:

```bash
# A Knot on this host; elsewhere, its address or hostname
sudo bindizr secondary create knot --address 127.0.0.1
```

For a remote server, use its address or hostname and Bindizr's reachable DNS
address in the configuration below. Registration is also needed when using
[signed transfers](#sign-the-transfers), so NOTIFY reaches the server.

## 2. Configure the catalog zone

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
sudo knotc -c /etc/knot/knot.conf conf-check
sudo systemctl restart knot
```

## 3. Check a zone it learned

`zone-status` names the catalog the zone came from, which tells a
catalog-provisioned zone from one configured by hand:

```bash
sudo knotc zone-status example.com
```

Example output:

```text
[example.com.] role: slave | serial: 12 | catalog: catalog.bindizr. | refresh: +22h59m46s
```

## Sign the transfers

The key goes on the `remote`, so Knot signs both the catalog transfer and
every member transfer the template derives from that remote:

```yaml
key:
  - id: xfr-key
    algorithm: hmac-sha256
    secret: <base64 secret from bindizr tsig-key create>
```

Add `key` to the existing `bindizr` remote; do not create a second remote
with the same ID. Use the address where Bindizr listens:

```yaml
remote:
  - id: bindizr
    address: 10.0.0.5@5300
    key: xfr-key
```

Keep the NOTIFY ACL matched by address unless you also register the
secondary with `--notify-key`. See
[Signed NOTIFY](../cli/secondaries.md#signed-notify).

See [Access Control](../cli/access-control.md#secondaries-pulling-over-tsig)
for creating the key in a role that holds `zone:transfer` in all zones.
