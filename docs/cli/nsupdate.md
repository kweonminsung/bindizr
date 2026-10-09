# Dynamic Updates (nsupdate)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. The key named in the request's TSIG record says who
is calling; the key's [role](access-control.md) says what it may change.

The role needs `record:read` for prerequisites, `record:create` for additions,
and `record:delete` for deletions. An addition that replaces a CNAME or DNAME
needs `record:delete` as well, and one whose TTL differs from the record set's
needs `record:update`, since it moves the whole set. If any record falls
outside its grants, the entire update is refused.

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

With `dns.nsupdate.tsig_required = true`, the default, an unsigned update is
refused for all zones.

!!! warning "Unsigned updates are for testing only"

    `dns.nsupdate.tsig_required = false` accepts unsigned requests for every
    zone from any client that reaches the DNS listener, as
    `api.authentication_required = false` does for the HTTP API. Signed
    requests are always verified either way.

## Response codes

The response follows RFC 2136, Section 2.2. `NOTAUTH` names a zone Bindizr
does not serve, `NOTZONE` an owner outside the zone named, `FORMERR` a
malformed section (a prerequisite with a TTL, a delete carrying rdata, a type
no update may carry, or a type Bindizr does not store in an add), and
`REFUSED` a policy decision: an unsigned request where a signature is
required, a key whose role does not reach what the update touches, or an
update sent to the TLS listener, which serves transfers alone (RFC 9103,
Section 7.8). A
request whose key verifies is answered under that key whatever the code; a
TSIG record that is doubled, not last, unreadable, or carries a MAC of a size
its algorithm cannot produce is a `FORMERR` signed by no one (RFC 8945,
Section 5.2). The
prerequisite codes (`NXDOMAIN`, `YXDOMAIN`, `NXRRSET`, `YXRRSET`) report the
first prerequisite that failed. A prerequisite may name the zone's SOA,
which no record holds but every zone serves, serial included.

Some records in an update are passed over rather than refused, as the RFC
says: a delete that would remove the SOA or the last apex NS record, a CNAME
added beside other data or data added beside a CNAME, a DNAME added beside a
CNAME, and a delete of a type Bindizr never stores. A second CNAME or DNAME
replaces the first, and an add whose TTL differs from the record set's moves
the whole set to the new TTL. A record below a DNAME, or a DNAME above
existing records, is refused: nothing may exist under a DNAME (RFC 6672,
Section 2.4).

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
