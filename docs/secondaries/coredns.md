# CoreDNS

CoreDNS's `secondary` plugin transfers a zone and serves it, but does not
read catalog zones, so each zone Bindizr serves is declared on it. Bindizr's
interoperability run covers CoreDNS 1.14.

## 1. Register the secondary in Bindizr

Register the server's address so it receives NOTIFY and can transfer zones.
This example uses a server on the same host, listening on port 53:

```bash
# A CoreDNS on this host; elsewhere, its address or hostname
sudo bindizr secondary create coredns --address 127.0.0.1
```

## 2. Add the zones

Declare each zone in the `Corefile` with Bindizr as its primary:

```text
example.com {
    secondary {
        transfer from 127.0.0.1:5300
    }
}
```

Several zones can share one block (`example.com example.net { … }`). A zone
created in Bindizr later needs adding there, and a deleted one removing.

## 3. Check a zone

```bash
dig +norec @127.0.0.1 example.com SOA
```

An authoritative answer carrying Bindizr's serial means the zone loaded.

## Transfers are AXFR

CoreDNS acts on NOTIFY, but always pulls the whole zone. Bindizr serves both,
so this costs bandwidth on large or frequently-changed zones but changes
nothing about what CoreDNS ends up serving.

## NSEC3-signed zones are refused

CoreDNS refuses a zone carrying NSEC3 records ("NSEC3 zone is not
supported") and keeps retrying the transfer. A zone signed under a policy
created with `--denial nsec` transfers and serves with its signatures. See
[DNSSEC Policies](../dnssec/policies.md).

## Transfers are unsigned

The `secondary` plugin has no TSIG, so the registered address is what
authorizes it.
