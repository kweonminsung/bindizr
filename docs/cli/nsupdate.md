# Dynamic Updates (nsupdate)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. The key named in the request's TSIG record says who
is calling; the key's [role](access-control.md) says what it may change.

The role needs `record:read` for prerequisites, `record:create` for additions,
and `record:delete` for deletions. If any record falls outside its grants,
the entire update is refused.

## Example

Create `example.com` first. Send updates to Bindizr's DNS listener, which uses
port 5300 in the packaged configuration; the secondary on port 53 answers
ordinary queries.

```bash
# A role that may manage A and TXT records under dyn.example.com
bindizr role create dyn-updates
bindizr role grant dyn-updates --zone example.com \
    --actions record:read,record:create,record:delete \
    --pattern '*.dyn' --types A,TXT

# Create a key in that role; `tsig-key get` can retrieve its secret later
bindizr tsig-key create update-key --role dyn-updates

# Send a signed update (hmac-sha256 by default)
nsupdate -y "hmac-sha256:update-key:<BASE64_SECRET>" <<EOF
server 127.0.0.1 5300
zone example.com
update add host.dyn.example.com. 300 A 192.0.2.1
send
EOF
```

## Unsigned requests

With `dns.nsupdate_tsig_required = true`, the default, an unsigned update is
refused for every zone.

!!! warning "Unsigned updates are for testing only"

    `dns.nsupdate_tsig_required = false` accepts unsigned requests for every
    zone from any client that reaches the DNS listener, as
    `api.authentication_required = false` does for the HTTP API. Signed
    requests are always verified either way.

## The first key

A TSIG key needs no bootstrapping of its own: with an API token whose role has
`access:manage`, a key is created over the HTTP API from anywhere.

```bash
curl -X POST https://bindizr:3000/tsig-keys \
  -H "Authorization: Bearer $BINDIZR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "update-key", "role_name": "dyn-updates"}'
```

The response includes the secret. Unlike an API token, a TSIG key's secret
can be retrieved later with `GET /tsig-keys/{name}` or `bindizr tsig-key get`.

A key updates only what its role's grants reach. See
[Access Control](access-control.md) for granting, and for an ACME DNS-01
example.
