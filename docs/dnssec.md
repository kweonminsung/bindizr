# DNSSEC

bindizr signs zones itself. When DNSSEC is enabled for a zone, bindizr
generates its signing key(s), derives the zone's `DNSKEY`, `CDS`/`CDNSKEY`,
denial-of-existence, and `RRSIG` records, and serves the signed zone over the
same AXFR/IXFR path as before — your BIND9 secondaries need **no
configuration changes** and serve the signed zone as-is. Every record change
re-signs exactly what changed within the same transaction, so an incremental
transfer always carries a consistent signed delta, and a background scheduler
renews signatures before they expire.

## Enabling DNSSEC for a zone

```sh
bindizr zone dnssec enable example.com
```

or over HTTP:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3000/zones/example.com/dnssec \
  -H "Content-Type: application/json" -d '{}'
```

This generates a single CSK (combined signing key, ECDSA P-256/SHA-256 by
default; pass `"algorithm": "ed25519"` or `--algorithm ed25519` for Ed25519),
signs the whole zone, bumps the serial, and notifies the secondaries. The
private key is stored server-side and never leaves bindizr; status responses
carry only the public half.

Two options are fixed at enable time:

`--denial nsec3` (`"denial": "nsec3"`)
:   Use `NSEC3` denial of existence instead of the default `NSEC`, with the
    RFC 9276 recommended parameters (SHA-1, zero iterations, no salt, no
    opt-out). NSEC lets anyone walk the zone's names; NSEC3 hashes them. For
    most managed zones NSEC is simpler and sufficient.

`--split-keys` (`"split_keys": true`)
:   Use a KSK/ZSK pair instead of one CSK. The KSK signs the apex key RRsets
    and is the only key the parent DS names; the ZSK signs the zone data and
    rolls without ever touching the parent. Choose this when you expect to
    roll data-signing keys often; a CSK is simpler otherwise.

## Completing the chain of trust

Signatures only validate once the parent zone delegates trust to your key.
Fetch the DS record and register it at your parent (usually through your
registrar):

```sh
bindizr zone dnssec ds example.com
```

```text
example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383
```

Signed zones also publish matching `CDS`/`CDNSKEY` records (RFC 7344), so a
parent that scans for them picks up DS changes automatically. Until the DS is
published the zone serves signatures but resolvers treat it as insecure —
safe to roll out gradually. Check the state at any time:

```sh
bindizr zone dnssec status example.com
```

## Key rollover

Rollover replaces a key without ever letting validation break, following the
pre-publish shape of RFC 7583:

```sh
bindizr zone dnssec rollover start example.com            # CSK zones
bindizr zone dnssec rollover start example.com --role zsk # split-key zones
```

`start` generates the replacement with the same algorithm and pre-publishes
it: the new key joins the `DNSKEY` RRset (and, for CSK/KSK, the `CDS`/
`CDNSKEY` set, advertising **both** DS records — the double-DS method) but
signs no zone data yet.

What happens next depends on the key:

- **ZSK** — no parent involvement, so after `rollover_publish_holddown_secs`
  (default one day, giving caches time to learn the new `DNSKEY`) the
  scheduler promotes it automatically: the new key signs everything, the old
  key is retired.
- **CSK / KSK** — the parent DS must change first. Publish the new DS at the
  parent (or let it consume the CDS), wait out the parent's DS TTL, then
  confirm. The confirmation is refused until the replacement has been
  published for `rollover_publish_holddown_secs`, and never for less than the
  zone's TTL — resolvers still holding the previous `DNSKEY` RRset could not
  validate the new key's signatures:

  ```sh
  bindizr zone dnssec rollover ds-seen example.com
  ```

A retired key stays in the `DNSKEY` RRset — cached signatures and a possibly
lingering old DS still need it — until `rollover_retire_holddown_secs`
(default two days) passes, when the scheduler removes it and the rollover is
complete. `status` shows every key's role and lifecycle state
(`published` / `active` / `retired`) throughout.

## Signature maintenance

Signatures are valid for `dnssec.signature_validity_days` (default 14) and are
renewed once fewer than `dnssec.signature_refresh_days` (default 5) remain.
The scheduler scans hourly, re-signs what is due, advances rollovers, bumps
serials, and notifies secondaries — no operator action is needed. `bindizr zone dnssec sign example.com` forces a
full re-sign if you ever doubt the stored signatures.

## Disabling DNSSEC

Turning signing off while the parent still publishes your DS makes the zone
**bogus** for validating resolvers. Go insecure in this order:

1. Remove the DS record at the parent.
2. Wait out the DS TTL.
3. `bindizr zone dnssec disable example.com`

Over HTTP the request body must acknowledge the procedure with
`{"confirm_insecure": true}`; without it the request is refused. The removal
propagates to secondaries as an ordinary incremental transfer.

## Behavior notes

- The denial mode (`nsec`/`nsec3`) and key layout (CSK vs KSK/ZSK) are chosen at
  enable time; to change them, disable and re-enable (going insecure in
  between, per the procedure above).
- Rollovers keep the key's algorithm. An algorithm change is a stricter
  procedure (RFC 6840, Section 5.11) and is not supported.
- Delegations follow RFC 4035: delegation `NS` RRsets and glue below a zone
  cut are served but not signed.
- Zone-file export and version diffs show user records only; the derived
  DNSSEC records are system-owned and re-generated, never edited or rolled
  back. Version listings likewise hide signer-only serials (re-signs,
  rollovers) unless `all` is requested.
