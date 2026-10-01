# YADIFA

YADIFA does not read catalog zones, so each zone Bindizr serves is declared on
it. Bindizr's interoperability run covers YADIFA 2.6, signed and unsigned,
with changes arriving as IXFR deltas.

## 1. Register the secondary in Bindizr

Register the server's address so it receives NOTIFY and can transfer zones.
This example uses a server on the same host, listening on port 53:

```bash
# A YADIFA on this host; elsewhere, its address or hostname
sudo bindizr secondary create yadifa --address 127.0.0.1
```

## 2. Add the zones

Declare each zone in `yadifad.conf` with Bindizr as its primary:

```text
<zone>
    type         slave
    domain       example.com
    file-name    example.com.zone
    master       127.0.0.1 port 5300
    allow-notify 127.0.0.1
</zone>
```

A zone created in Bindizr later needs its own `<zone>` block, and a deleted
one its block removed, followed by a restart of `yadifad`.

## 3. Check a zone

```bash
dig +norec @127.0.0.1 example.com SOA
```

An authoritative answer carrying Bindizr's serial means the zone loaded.

## YADIFA 3.0.9 crashed on startup

YADIFA 3.0.9 as packaged by Alpine crashed on startup in the same run, with a
BIND primary as well, so the crash is not Bindizr's. Use 2.6 until it is fixed.

## Sign the transfers

Declare the key, then name it on `master`:

```text
<key>
    name      xfr-key
    algorithm hmac-sha256
    secret    <base64 secret from bindizr tsig-key create>
</key>

<zone>
    ...
    master    10.0.0.5 key xfr-key
</zone>
```

See [Access Control](../cli/access-control.md#secondaries-pulling-over-tsig)
for creating the key in a role that holds `zone:transfer` in every zone.
