# DNSSEC

Bindizr signs zones and sends the signed records to secondaries over AXFR/IXFR.
Secondaries need no signing configuration. Record changes update signatures,
and the background scheduler renews them before expiry and advances
[key rollovers](rollover.md).

A [DNSSEC policy](policies.md) controls the algorithm, key layout, and timing.
The built-in `default` uses one ECDSA P-256 combined signing key (CSK) and
NSEC3. To retain keys from another signer, use [Key Import and Export](keys.md).

## Enabling DNSSEC for a zone

For an existing zone, supply the parent zone's authoritative name servers.
This example uses the default policy:

```sh
bindizr dnssec enable example.com \
  --parent-ns-addrs a.gtld-servers.net,b.gtld-servers.net
```

The equivalent HTTP request is:

```sh
curl -X POST -H "Authorization: Bearer $BINDIZR_TOKEN" \
  http://127.0.0.1:3000/zones/example.com/dnssec \
  -H "Content-Type: application/json" \
  -d '{"parent_ns_addrs": ["a.gtld-servers.net", "b.gtld-servers.net"]}'
```

Bindizr generates keys, signs the zone, and notifies secondaries.
`--parent-ns-addrs` is required: subsequent DS checks query these servers, so
Bindizr must be able to reach them. Use `host[:port]` entries; change them later
with `bindizr dnssec set example.com --parent-ns-addrs <servers>`.

## Completing the chain of trust

Publish the DS record at the parent, usually through your registrar. The
enable response and `bindizr dnssec status example.com` show the record:

```text
DS records (register in the parent zone):
  example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383
```

Use the DS from your own zone, then check the parent:

```sh
bindizr dnssec check-ds example.com
```

Signed zones also publish `CDS`/`CDNSKEY` for parents that support automatic
DS updates. Until a matching DS is published, resolvers treat a newly signed
zone with no previous DS as insecure.

## Changing the signing policy

After [creating a policy](policies.md), move a signed zone to it:

```sh
bindizr dnssec set example.com --policy strict
```

Over HTTP, send `policy_name` in `PUT /zones/{name}/dnssec`.

- A new algorithm starts an [algorithm rollover](rollover.md#algorithm-rollover).
- A new denial mode replaces the NSEC/NSEC3 records in one serial.
- Timing changes apply from the next signing pass.
- A different key layout (CSK versus KSK/ZSK) requires disabling DNSSEC and
  re-enabling it under the new policy. Follow the DS removal procedure below.

## Disabling DNSSEC

Removing signatures while the parent still publishes a DS breaks validation.
Disable signing in this order:

1. Remove the DS at the registrar. If the parent processes CDS withdrawal,
   `bindizr dnssec withdraw start example.com` publishes the RFC 8078 delete
   pair instead. `bindizr dnssec withdraw cancel example.com` cancels that request.
2. Run `bindizr dnssec check-ds example.com` to confirm removal, then wait out
   the previously published DS TTL so cached copies expire.
3. Run `bindizr dnssec disable example.com`.

Disable is refused while any configured parent server still publishes a DS
(`DNSSEC_DS_PUBLISHED`) or cannot confirm its absence (`DNSSEC_DS_UNVERIFIED`).
`--skip-ds-check` bypasses that check; use it only when you have independently
verified removal and waited out the TTL.

## Behavior notes

The scheduler runs hourly by default (`dns.scheduler_interval_secs`).
`dnssec status` reports the parent DS TTL, which also affects key retirement.
See [Advanced DNSSEC](advanced.md) for delegation signing, generated records,
and version history.
