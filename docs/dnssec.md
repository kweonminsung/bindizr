# DNSSEC

bindizr signs zones itself: enabling DNSSEC generates the zone's key(s),
derives the `DNSKEY`, `CDS`/`CDNSKEY`, denial-of-existence, and `RRSIG`
records, and serves them over the same AXFR/IXFR path — secondaries need
**no configuration changes**. Every record change re-signs exactly what
changed in the same transaction, and a background scheduler renews
signatures before they expire.

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

This generates a single CSK (ECDSA P-256/SHA-256 by default; `--algorithm`
selects `ecdsap384sha384`, `ed25519`, `ed448`, `rsasha256`, or `rsasha512`
instead — every algorithm RFC 8624 permits for signing; RSA keys are
2048-bit), signs the whole zone, and notifies the secondaries. P-384 keys
advertise a SHA-384 DS digest (type 4); the others SHA-256 (type 2).
The private key never leaves bindizr.

Two options are fixed at enable time:

`--denial nsec3` (`"denial": "nsec3"`)
:   `NSEC3` denial of existence (RFC 9276 parameters) instead of the default
    `NSEC`. NSEC lets anyone walk the zone's names; NSEC3 hashes them.

`--split-keys` (`"split_keys": true`)
:   A KSK/ZSK pair instead of one CSK: the KSK is the only key the parent DS
    names, so the ZSK rolls without touching the parent. A CSK is simpler
    otherwise.

## Completing the chain of trust

Signatures only validate once the parent delegates trust to your key. Fetch
the DS record and register it at your parent (usually via your registrar):

```sh
bindizr zone dnssec ds example.com
```

```text
example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383
```

Signed zones also publish `CDS`/`CDNSKEY` (RFC 7344) for parents that scan
for DS changes. Until the DS is published, resolvers simply treat the zone
as insecure — safe to roll out gradually. `bindizr zone dnssec status
example.com` shows the signing state at any time.

## Key rollover

Rollover replaces a key without breaking validation (RFC 7583 pre-publish):

```sh
bindizr zone dnssec rollover start example.com            # CSK zones
bindizr zone dnssec rollover start example.com --role zsk # split-key zones
```

`start` pre-publishes a replacement with the same algorithm: it joins the
`DNSKEY` RRset (and, for CSK/KSK, the CDS/CDNSKEY set — both DS records
advertised) but signs nothing yet. The publication wait —
`rollover_publish_holddown_secs` (default one day), never less than the
zone's `DNSKEY` TTL, fixed when the key is published — gives resolver caches
time to learn the new key. Then:

`--algorithm <alg>` starts an algorithm rollover (RFC 6840, Section 5.11)
instead: every key is replaced with one of the new algorithm and the zone is
double-signed — both algorithms cover all data — until the old keys leave
together after `ds-seen`.

- **ZSK** — no parent involvement: the scheduler promotes it automatically
  after the wait. With `dnssec.zsk_lifetime_days` set (0, the default,
  disables it), the scheduler also *starts* ZSK rollovers on its own once the
  active ZSK outlives that many days, making split-key ZSK rotation fully
  hands-off. CSKs are never auto-rolled — their rollover needs the parent DS
  swap below.
- **CSK / KSK** — publish the new DS at the parent (or let it consume the
  CDS), wait out the parent's DS TTL, then confirm; an early confirmation is
  refused:

  ```sh
  bindizr zone dnssec rollover ds-seen example.com
  ```

  With `dnssec.ds_probe_resolver` set, `ds-seen` first asks that resolver for
  the zone's DS RRset and refuses unless the new key's DS is actually
  visible — the guard against confirming a DS the parent never published.
  `--force` (API: `?force=true`) skips the check.

A retired key stays published until its own wait passes —
`rollover_retire_holddown_secs` (default two days), never less than the
largest TTL among the RRsets it signed — then the scheduler removes it.
`status` shows every key's state (`published`/`active`/`retired`)
throughout.

## Signature maintenance

Signatures are valid for `dnssec.signature_validity_days` (default 14) and
renewed once fewer than `dnssec.signature_refresh_days` (default 5) remain;
the hourly scheduler handles this with no operator action. `bindizr zone
dnssec sign example.com` forces a full re-sign if stored signatures are ever
doubted.

### Per-zone timing

The three day-scale knobs — signature validity, the re-sign threshold, and
the scheduled ZSK lifetime — can be overridden per zone:

```bash
$ bindizr zone dnssec timing example.com \
    --signature-validity-days 30 --zsk-lifetime-days 90
```

Also `PUT /zones/{name}/dnssec/timing`. The call **replaces** the zone's
overrides: a knob whose flag is omitted reverts to the global `[dnssec]`
config. `--zsk-lifetime-days 0` turns scheduled ZSK rolls off for one zone
while others keep rolling. `zone dnssec status` reports the effective values
and which are overridden; changes take effect on the next signing pass or
maintenance scan.

## Disabling DNSSEC

Dropping signatures while the parent still publishes your DS makes the zone
**bogus**. Go insecure in order:

1. Ask the parent to remove the DS. If the parent consumes CDS,
   `bindizr zone dnssec withdraw example.com` publishes the RFC 8078 delete
   pair (`CDS 0 0 0 00`) and the parent drops the DS on its own; otherwise
   remove it at the registrar. `--cancel` takes a withdrawal back.
2. Wait until the DS is gone and its TTL has passed.
3. `bindizr zone dnssec disable example.com`

## Verifying

```sh
bindizr zone dnssec verify example.com
```

Runs self-checks on the stored state — key inventory, signature freshness,
per-algorithm signature coverage, and the denial chain — and, with
`dnssec.ds_probe_resolver` configured, compares the DS records the parent
actually serves against the zone's keys. Also available as
`GET /zones/{name}/dnssec/verify`.

## Behavior notes

- Denial mode and key layout are fixed at enable time; to change them,
  disable and re-enable (going insecure in between).
- An algorithm change is a rollover of every key:
  `rollover start --algorithm <alg>` double-signs the zone through the
  transition (RFC 6840, Section 5.11).
- At a delegation only the child's `DS` RRset is signed; the `NS` beside it
  and glue at or below the cut are served unsigned (RFC 4035).
- The derived records are system-owned: never edited, diffed, or rolled
  back. Version listings hide signer-only serials unless `all` is requested;
  `record list --signed` (`GET /records?signed=true`) pages them after the
  user records.
