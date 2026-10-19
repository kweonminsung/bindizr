# nsupdate

Bindizr serves nsupdate, the RFC 2136 UPDATE message, through the DNS listener,
authenticated with TSIG. The key named in the request's TSIG record says who
is calling; the key's [role](access-control.md) says what it may change.

Only the [implemented user record types](zones.md) are accepted. Unsupported
ordinary types receive `REFUSED` in prerequisites and updates, including deletes;
the entire request leaves records and the serial unchanged.

A WKS addition replaces the WKS at the same name, IPv4 address, and protocol.
Different addresses or protocols can coexist.

The role needs `record:read` for prerequisites, `record:create` for ordinary additions,
and `record:delete` for deletions. An addition that replaces a CNAME, DNAME, or matching WKS record
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

Each signed request must pass MAC verification and its Time Signed/Fudge
window. Bindizr does not retain a latest Time Signed per key: UDP and
concurrent stream requests can arrive out of order. This is an explicit
exception to the cache recommendation in
[RFC 8945, Section 5.2.3](https://www.rfc-editor.org/rfc/rfc8945.html#section-5.2.3).

## Response codes

The response follows RFC 2136, Section 2.2. `NOTAUTH` names a zone or class
Bindizr does not serve: only IN is served, even when another class names an
existing zone (Section 3.1.1). `NOTZONE` names an owner outside the zone,
`FORMERR` a malformed section (a prerequisite with a TTL, an ANY-class delete carrying
rdata, malformed wire RDATA, or a query/meta type no update may carry), and
`REFUSED` a policy decision: an unsigned request where a signature is
required, a key whose role does not reach what the update touches, an
unsupported ordinary type, a direct addition or deletion of signer-managed
DNSSEC records, or an update sent to the TLS listener, which serves transfers alone (RFC 9103,
Section 7.8). A
request whose key verifies is answered under that key whatever the code; a
TSIG record outside Additional, doubled, not last, unreadable, or carrying a MAC of a size
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
CNAME. Every update record
must first pass the zone and wire-shape checks, including a delete that will
be ignored (RFC 2136, Section 3.4.1). An out-of-zone owner or forbidden
query/meta type rejects the whole update without changing records or the
serial. A second CNAME or DNAME
replaces the first. A WKS addition replaces the record with the same owner,
address, and protocol; other addresses and protocols remain. An add whose TTL differs from its name and type's current TTL moves all
those records to the new TTL. A record below a DNAME, or a DNAME above
existing records, is refused: nothing may exist under a DNAME (RFC 6672,
Section 2.4).

An SOA addition replaces the apex SOA only when its serial advances under
RFC 1982. Equal or older serials, the undefined half-range distance, and SOAs
at other owners are ignored. Multiple SOAs are considered in request order.
The accepted serial is used for all changes in that request; automatic
incrementing applies only when records change without an SOA advance
(RFC 2136, Sections 3.4.2.2 and 3.6).

SOA replacements accept serials 0–4294967295, with wraparound comparison and
automatic incrementing under RFC 1982. The zone-write policy requires SOA TTL 60–604800 seconds, refresh/retry/expire from 1–2147483647 seconds, minimum TTL from
1–4294967295 seconds, a supported MNAME and an email-convertible RNAME. A newer SOA
outside that policy refuses the whole request with `REFUSED`.

Record TTLs accept 0–4294967295 and retain the high bit as part of the value
([RFC 8767, Section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4)).

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
