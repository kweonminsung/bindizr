# CoreDNS

Catalog zones need **CoreDNS 1.14.6 or newer**, whose `secondary` plugin
gained a `catalog` option; Bindizr's interoperability run covers 1.14.6 and
1.14.7. An older CoreDNS takes each zone by hand; see
[CoreDNS before 1.14.6](#coredns-before-1146).

## 1. Register the secondary in Bindizr

Register the server's address so it receives NOTIFY and can transfer zones.
This example uses a server on the same host, listening on port 53:

```bash
# A CoreDNS on this host; elsewhere, its address or hostname
sudo bindizr secondary create coredns --address 127.0.0.1
```

## 2. Configure the catalog zone

`catalog` makes the plugin read the zone it transfers as a catalog: it adds
and removes the member zones the catalog names and transfers each from the
same primary. Add this to the `Corefile`:

```text
. {
    secondary catalog.bindizr {
        transfer from 127.0.0.1:5300
        catalog
    }
}
```

The root (`.`) block is what lets the member zones answer: CoreDNS picks a
server block by the query's name, so a block named `catalog.bindizr` alone
answers REFUSED for `example.com`. Where the `Corefile` already has a root
block, add `secondary` to it rather than a second one. CoreDNS takes NOTIFY
only from the addresses on `transfer from`.

## 3. Check a zone it learned

```bash
dig +norec @127.0.0.1 example.com SOA
```

An authoritative answer carrying Bindizr's serial means the member zone
loaded.

## CoreDNS before 1.14.6

An older CoreDNS refuses `catalog` ("unknown property") and takes each zone
in a block of its own; the interoperability run covers 1.14.4:

```text
example.com {
    secondary {
        transfer from 127.0.0.1:5300
    }
}
```

Several zones can share one block (`example.com example.net { … }`). A zone
created in Bindizr later needs adding there, and a deleted one removing.

## Transfers are AXFR

CoreDNS acts on NOTIFY, but always pulls the whole zone. Bindizr serves both,
so this costs bandwidth on large or frequently-changed zones but changes
nothing about what CoreDNS ends up serving.

## NSEC3-signed zones are refused

CoreDNS refuses a zone carrying NSEC3 records ("NSEC3 zone is not
supported") and keeps retrying the transfer; a zone it already held stays at
that copy. A zone signed under a policy created with `--denial nsec`
transfers and serves with its signatures. See
[DNSSEC Policies](../dnssec/policies.md).

## Transfers are unsigned

The `secondary` plugin has no TSIG, so the registered address is what
authorizes it.
