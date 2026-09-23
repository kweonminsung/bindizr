# Dynamic Updates (nsupdate)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. Authorization is built from two pieces:

**Keys**
:   Standalone, reusable resources (name, HMAC algorithm, base64 secret). The
    key name is what appears on the wire in a signed request. A key created with
    `--global` may update every zone — including zones created later — without
    any grant; this is fixed at creation.

**Grants**
:   Give a non-global key update rights in one zone, optionally restricted to a
    record name pattern and record types.

For each incoming update, Bindizr resolves the key named in the TSIG record and
verifies the signature and signing time. A global key is then authorized for
everything; for any other key, Bindizr loads its grants for the target zone
and every record in the update must match at least one of them (name pattern and
type). Otherwise the whole update is refused and nothing is partially applied.

## Example

```bash
# Create a key (the secret is generated and printed once; use `get` to re-read it)
$ bindizr tsig-key create update-key

# Or import an existing base64 secret / pick another HMAC algorithm
$ bindizr tsig-key create legacy-key --algorithm hmac-sha512 --secret "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="

# Or create a global key that may update every zone, including future ones,
# without any grant. This is write access to all DNS data — use sparingly.
$ bindizr tsig-key create admin-key --global

# Grant a (non-global) key update rights in a zone (pattern/types default to '*')
$ bindizr tsig-key grant update-key example.com
$ bindizr tsig-key grant acme-key example.com --pattern "*" --types "TXT"

# Send a signed update (hmac-sha256 by default)
$ nsupdate -y "hmac-sha256:update-key:<BASE64_SECRET>" <<EOF
server 127.0.0.1 53
zone example.com
update add sub.example.com. 300 A 1.2.3.4
send
EOF
```

## Unsigned requests

A zone no key has been granted refuses nsupdate, except from global keys,
which may update any zone.

!!! warning "Turning off `tsig_required` covers testing only"

    `dns.nsupdate_tsig_required = false` accepts unsigned requests for every
    zone from any client that reaches the DNS listener, as
    `api.authentication_required = false` does for the HTTP API. Signed
    requests are always verified either way.

## The first key

A TSIG key needs no bootstrapping of its own: with a global API token, a key
is created over the HTTP API from anywhere.

```bash
$ curl -X POST https://bindizr:3000/tsig-keys \
  -H "Authorization: Bearer $BINDIZR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "update-key"}'
```

The secret comes back in that response, shown once; `bindizr tsig-key create
update-key` does the same where the CLI can be run.

A key updates only what its grants reach. `--global` (or `"is_global": true`)
makes one that needs none, which is worth avoiding where you can grant instead.
