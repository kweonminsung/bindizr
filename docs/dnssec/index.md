# DNSSEC

Bindizr signs zones itself: enabling DNSSEC generates the zone's key(s),
derives the `DNSKEY`, `CDS`/`CDNSKEY`, denial-of-existence, and `RRSIG`
records, and serves them over the same AXFR/IXFR path — secondaries need
**no configuration changes**. Every record change re-signs exactly what
changed, in the same serial, and a scheduler pass — hourly by default,
set by `dns.scheduler_interval_secs` — renews signatures before they expire
and carries [key rollovers](rollover.md) through, asking the parent about the
DS when one is waiting on it.

How a zone is signed is described by a [DNSSEC policy](policies.md), a named
bundle of signing parameters that zones reference; a `default` policy is
seeded at startup. Keys move in and out as BIND key files — see
[Key Import and Export](keys.md).

## Enabling DNSSEC for a zone

```sh
bindizr dnssec enable example.com \
  --parent-ns-addrs a.gtld-servers.net,b.gtld-servers.net
bindizr dnssec enable example.com \
  --parent-ns-addrs ns1.parent.example --policy strict
```

or over HTTP:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3000/zones/example.com/dnssec \
  -H "Content-Type: application/json" \
  -d '{"policy_name": "strict", "parent_ns_addrs": ["ns1.parent.example"]}'
```

`--parent-ns-addrs` is required, and names the servers every later DS check
asks — in a hidden primary layout the host resolver cannot see the zones
Bindizr serves, so there is nothing reliable to guess them from. The TTL those
servers hand out with the zone's DS is read from their answer, not configured,
and `dnssec status` reports it: a retired SEP key waits it out, so a long
parent TTL lengthens a rollover.

This generates the key(s) the policy prescribes (under `default`, a single
ECDSA P-256 CSK), signs the whole zone, and notifies the secondaries. The
private key never leaves bindizr.

A signed zone moves to another policy with:

```sh
bindizr dnssec set example.com --policy strict
```

Also `policy_name` in `PUT /zones/{name}/dnssec`. The target must share the zone's
key layout — that has no safe in-place transition, so to change it disable
DNSSEC and re-enable under the new policy, going insecure in between. A
different denial mode is replaced in place under one serial: every algorithm
Bindizr signs with is NSEC3-capable (RFC 5155, Section 2), so a resolver that
could follow the old chain already understands the new one. A different
algorithm starts an [algorithm rollover](rollover.md#algorithm-rollover); different timing
simply applies from the next signing pass.

## Completing the chain of trust

Signatures only validate once the parent delegates trust to your key. The
DS record to register at your parent (usually via your registrar) is in the
enable output and in `bindizr dnssec status example.com` (`ds_records` of
`GET /zones/{name}/dnssec`):

```text
DS records (register in the parent zone):
  example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383
```

Signed zones also publish `CDS`/`CDNSKEY` (RFC 7344) for parents that scan
for DS changes. Until the DS is published, resolvers simply treat the zone
as insecure — safe to roll out gradually.

## Disabling DNSSEC

Dropping signatures while the parent still publishes your DS makes the zone
**bogus**, so `dnssec disable` asks the parent's name servers for the DS
first and refuses while any still serves one (`DNSSEC_DS_PUBLISHED`) or
fails to answer (`DNSSEC_DS_UNVERIFIED`). Go insecure in order:

1. Ask the parent to remove the DS. If the parent consumes CDS,
   `bindizr dnssec withdraw start example.com` publishes the RFC 8078
   delete pair (`CDS 0 0 0 00`) and the parent drops the DS on its own;
   otherwise remove it at the registrar. `bindizr dnssec withdraw cancel`
   takes a withdrawal back.
2. Wait until the DS is gone and its TTL has passed. `bindizr dnssec
   check-ds example.com` (`POST /zones/{name}/dnssec/check-ds`) shows what
   the parent serves now and its TTL; the wait itself is yours.
3. `bindizr dnssec disable example.com`

`--skip-ds-check` (`DELETE /zones/{name}/dnssec?skip_ds_check=true`) skips
the check, for a host that cannot reach the parent at all.

Every check asks the name servers the zone names — including the scheduler's,
so a host running Bindizr needs outbound DNS to them. Set at enable and
changed with:

```sh
bindizr dnssec set example.com --parent-ns-addrs ns1.parent.example:5353
```

The same field is `parent_ns_addrs`, a list of `host[:port]` entries, in the
enable body and in `PUT /zones/{name}/dnssec`, and it must always name at
least one server.
`dnssec status` shows it beside the DS TTL the parent answers with, which is
read rather than configured: it is how long caches may keep serving a DS
after its removal, and it paces a rollover's retirement.

## Behavior notes

- At a delegation only the child's `DS` records are signed; the `NS` records
  beside them and glue at or below the cut are served unsigned (RFC 4035).
- The derived records are system-owned: never edited, diffed, or rolled
  back. Version listings hide signer-only serials unless
  `include_signer_serials` is requested;
  `record list --signed` (`GET /records?signed=true`) pages them after the
  user records.
