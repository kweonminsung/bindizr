# nsupdate

Bindizr serves nsupdate, the RFC 2136 UPDATE message, through the DNS listener,
authenticated with TSIG. The key named in the request's TSIG record says who
is calling; the key's [role](access-control.md) says what it may change.

The role needs `record:read` for prerequisites, `record:create` for ordinary additions,
and `record:delete` for deletions. An addition that replaces a CNAME or DNAME
needs `record:delete` as well, and one whose TTL differs from the record set's
needs `record:update`, since it moves the whole set. An SOA addition needs
`zone:update`, since it changes the zone's metadata. If any record falls
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

The response follows RFC 2136, Section 2.2. `NOTAUTH` names a zone or class
Bindizr does not serve: only IN is served, even when another class names an
existing zone (Section 3.1.1). `NOTZONE` names an owner outside the zone,
`FORMERR` a malformed section (a prerequisite with a TTL, a delete carrying
rdata, a type no update may carry, or a type Bindizr does not store in an add), and
`REFUSED` a policy decision: an unsigned request where a signature is
required, a key whose role does not reach what the update touches, or an
update sent to the TLS listener, which serves transfers alone (RFC 9103,
Section 7.8). A
request whose key verifies is answered under that key whatever the code; a
TSIG record that is doubled, not last, unreadable, or carries a MAC of a size
its algorithm cannot produce is a `FORMERR` signed by no one (RFC 8945,
Section 5.2). The
prerequisite codes (`NXDOMAIN`, `YXDOMAIN`, `NXRRSET`, `YXRRSET`) report the
first prerequisite that failed. Prerequisites read the whole served zone:
ordinary records, the SOA (serial included), and generated DNSSEC records.
A name holding only DNSSEC records is in use. Value-dependent prerequisites
must match the entire RRset; order, duplicates, and TTL do not affect equality
(RFC 2136, Section 3.2). All checks use the same locked zone state as the update.

Some records in an update are passed over rather than refused, as the RFC
says: a delete that would remove the SOA or the last apex NS record, a CNAME
added beside other data or data added beside a CNAME, a DNAME added beside a
CNAME, and a delete of a data type Bindizr never stores. Every update record
must first pass the zone and wire-shape checks, including a delete that will
be ignored (RFC 2136, Section 3.4.1). An out-of-zone owner or forbidden
query/meta type rejects the whole update without changing records or the
serial. A second CNAME or DNAME
replaces the first, and an add whose TTL differs from the record set's moves
the whole set to the new TTL. A record below a DNAME, or a DNAME above
existing records, is refused: nothing may exist under a DNAME (RFC 6672,
Section 2.4).

An SOA addition replaces the apex SOA only when its serial advances under
RFC 1982. Equal or older serials, the undefined half-range distance, and SOAs
at other owners are ignored. Multiple SOAs are considered in request order.
The accepted serial is used for all changes in that request; automatic
incrementing applies only when records change without an SOA advance
(RFC 2136, Sections 3.4.2.2 and 3.6).

SOA replacements use the existing zone-write policy: serials at most
2147483647, SOA TTL 60–604800 seconds, positive timing fields at most
2147483647, a supported MNAME and an email-convertible RNAME. A newer SOA
outside that policy refuses the whole request with `REFUSED`.

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
