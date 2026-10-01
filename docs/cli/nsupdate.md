# Dynamic Updates (nsupdate)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. The key named in the request's TSIG record says who
is calling; the key's [role](access-control.md) says what it may change.

For each incoming update, Bindizr resolves the key named in the TSIG record and
verifies the signature and signing time. Every record in the update is then
checked against the key's role: a prerequisite needs `record:read`, an add
`record:create`, and a delete `record:delete`, each at the record's name and
type in the target zone. If any record falls outside the role, the whole
update is refused and nothing is partially applied.

## Example

```bash
# A role that may manage A and TXT records under dyn.example.com
$ bindizr role create dyn-updates
$ bindizr role grant dyn-updates --zone example.com \
    --actions record:read,record:create,record:delete \
    --pattern '*.dyn' --types A,TXT

# Create a key in that role (the secret is generated and printed once; use `get` to re-read it)
$ bindizr tsig-key create update-key --role dyn-updates

# Or import an existing base64 secret / pick another HMAC algorithm
$ bindizr tsig-key create legacy-key --role dyn-updates --algorithm hmac-sha512 --secret "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="

# Send a signed update (hmac-sha256 by default)
$ nsupdate -y "hmac-sha256:update-key:<BASE64_SECRET>" <<EOF
server 127.0.0.1 53
zone example.com
update add host.dyn.example.com. 300 A 1.2.3.4
send
EOF
```

## Unsigned requests

With `dns.nsupdate_tsig_required = true`, the default, an unsigned update is
refused for every zone.

!!! warning "Turning off `tsig_required` covers testing only"

    `dns.nsupdate_tsig_required = false` accepts unsigned requests for every
    zone from any client that reaches the DNS listener, as
    `api.authentication_required = false` does for the HTTP API. Signed
    requests are always verified either way.

## The first key

A TSIG key needs no bootstrapping of its own: with an API token whose role has
`access:manage`, a key is created over the HTTP API from anywhere.

```bash
$ curl -X POST https://bindizr:3000/tsig-keys \
  -H "Authorization: Bearer $BINDIZR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "update-key", "role_name": "dyn-updates"}'
```

The secret comes back in that response, shown once; `bindizr tsig-key create
update-key --role dyn-updates` does the same where the CLI can be run.

A key updates only what its role's grants reach. See
[Access Control](access-control.md) for granting, and for an ACME DNS-01
example.
