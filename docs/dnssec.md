# DNSSEC

bindizr signs zones itself: enabling DNSSEC generates the zone's key(s),
derives the `DNSKEY`, `CDS`/`CDNSKEY`, denial-of-existence, and `RRSIG`
records, and serves them over the same AXFR/IXFR path — secondaries need
**no configuration changes**. Every record change re-signs exactly what
changed in the same transaction, and a background scheduler renews
signatures before they expire.

How a zone is signed is described by a **DNSSEC policy**, a named bundle of
signing parameters that zones reference — the same shape as BIND's
`dnssec-policy` and Knot's `policy`. A `default` policy is seeded at
startup; create others when zones need a different algorithm, denial mode,
key layout, or timing.

## Policies

```sh
bindizr dnssec-policy list
bindizr dnssec-policy create --name strict --algorithm ed25519 --denial nsec3 \
    --signature-validity-days 7 --signature-refresh-days 3
bindizr dnssec-policy get strict
bindizr dnssec-policy update strict --zsk-lifetime-days 90
bindizr dnssec-policy delete strict
```

Also `GET`/`POST /dnssec-policies` and `GET`/`PUT`/`DELETE
/dnssec-policies/{name}`. A policy carries:

`algorithm`
:   `ecdsap256sha256` (default), `ecdsap384sha384`, `ed25519`, `ed448`,
    `rsasha256`, or `rsasha512` — every algorithm RFC 8624 permits for
    signing; RSA keys are 2048-bit. P-384 keys advertise a SHA-384 DS digest
    (type 4); the others SHA-256 (type 2).

`denial`
:   `nsec` (default) or `nsec3` (RFC 9276 parameters). NSEC lets anyone walk
    the zone's names; NSEC3 hashes them.

`split_keys`
:   A KSK/ZSK pair instead of one CSK: the KSK is the only key the parent DS
    names, so the ZSK rolls without touching the parent. A CSK is simpler
    otherwise.

`signature_validity_days` / `signature_refresh_days`
:   How long a new signature stays valid (default 14) and how many days
    before expiry it is renewed (default 5). The refresh window must be
    shorter than the validity.

`zsk_lifetime_days`
:   Roll the ZSK of split-key zones automatically once it has signed this
    long; 0 (the default) disables scheduled rolls.

`rollover_publish_holddown_secs` / `rollover_retire_holddown_secs`
:   How long a pre-published key stays visible before it may sign (default
    one day) and how long a retired key stays published before removal
    (default two days). Neither ever drops below the TTLs involved; see
    [Key rollover](#key-rollover).

The algorithm, denial mode, and key layout are fixed once a policy exists;
the timing fields can be edited in place and apply to every zone under the
policy from its next signing pass or maintenance scan. A policy in use
cannot be deleted, and neither can `default`: edit it to change the
installation's defaults.

## Enabling DNSSEC for a zone

```sh
bindizr zone dnssec enable example.com                  # the default policy
bindizr zone dnssec enable example.com --policy strict
```

or over HTTP:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3000/zones/example.com/dnssec \
  -H "Content-Type: application/json" -d '{"policy": "strict"}'
```

This generates the key(s) the policy prescribes (under `default`, a single
ECDSA P-256 CSK), signs the whole zone, and notifies the secondaries. The
private key never leaves bindizr.

A signed zone moves to another policy with:

```sh
bindizr zone dnssec set-policy example.com strict
```

Also `PUT /zones/{name}/dnssec/policy`. The target must share the zone's
denial mode and key layout — those have no safe in-place transition, so to
change them disable DNSSEC and re-enable under the new policy, going
insecure in between. A different algorithm starts an
[algorithm rollover](#key-rollover); different timing simply applies from
the next signing pass.

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
advertised) but signs nothing yet. The publication wait — the policy's
`rollover_publish_holddown_secs` (default one day), never less than the
zone's `DNSKEY` TTL, fixed when the key is published — gives resolver caches
time to learn the new key. Then:

An **algorithm rollover** (RFC 6840, Section 5.11) is started by moving the
zone to a policy of the new algorithm (`zone dnssec set-policy`): every key is
replaced with one of the new algorithm and the zone is double-signed — both
algorithms cover all data — until the old keys leave together after
`ds-seen`.

- **ZSK** — no parent involvement: the scheduler promotes it automatically
  after the wait. With the policy's `zsk_lifetime_days` set (0, the default,
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

  bindizr takes the confirmation at its word: check with `dig DS` that the
  parent serves the new DS before giving it, since promoting a key whose DS
  is not yet published makes the zone bogus for validating resolvers.

A retired key stays published until its own wait passes — the policy's
`rollover_retire_holddown_secs` (default two days), never less than the
largest TTL among the RRsets it signed — then the scheduler removes it.
`status` shows every key's state (`published`/`active`/`retired`)
throughout.

## Signature maintenance

Signatures are valid for the policy's `signature_validity_days` (default 14)
and renewed once fewer than `signature_refresh_days` (default 5) remain; the
hourly scheduler handles this with no operator action. `bindizr zone dnssec
sign example.com` forces a full re-sign if stored signatures are ever
doubted.

To give some zones different timing, create a policy with the values you
want and move them to it with `zone dnssec set-policy`; editing a policy
with `dnssec-policy update` changes every zone under it from the next
signing pass or maintenance scan. `zone dnssec status` reports the zone's
policy and its values.

## Key import and export

Keys move in and out as BIND key files, so a zone signed by BIND (or any
signer using that format) migrates without breaking its chain of trust:

```sh
# Print every key in BIND key-file form, split by `; K*.key` / `; K*.private`
# headers naming the file each block belongs in
bindizr zone dnssec keys export example.com

# Bring an existing key set in as active keys and sign with it
bindizr zone dnssec keys import example.com \
    --key Kexample.com.+013+12345.key --private Kexample.com.+013+12345.private
```

The export stream contains the private keys — redirect it only somewhere
with tight permissions.

Import takes the zone's complete key set in one call and signs on the spot:
one CSK pair, or a KSK pair and a ZSK pair (repeat `--key`/`--private`)
under a split-key policy. The policy (`--policy`, or `default`) decides what
the keys must be: its algorithm, and its key layout, which is what types a
SEP key (flags 257) as the CSK or the KSK — a 256-flag key is always the
ZSK. The zone must be unsigned; a signed zone changes keys through
[rollover](#key-rollover) instead. Both commands run only over the
CLI/daemon socket — private keys never transit the HTTP API.

## Disabling DNSSEC

Dropping signatures while the parent still publishes your DS makes the zone
**bogus**. Go insecure in order:

1. Ask the parent to remove the DS. If the parent consumes CDS,
   `bindizr zone dnssec withdraw example.com` publishes the RFC 8078 delete
   pair (`CDS 0 0 0 00`) and the parent drops the DS on its own; otherwise
   remove it at the registrar. `--cancel` takes a withdrawal back.
2. Wait until the DS is gone and its TTL has passed.
3. `bindizr zone dnssec disable example.com`

## Behavior notes

- A zone's denial mode and key layout are those of its policy and have no
  in-place transition; to change them, disable and re-enable under another
  policy (going insecure in between).
- An algorithm change is a rollover of every key: moving the zone to a
  policy of another algorithm double-signs the zone through the transition
  (RFC 6840, Section 5.11).
- At a delegation only the child's `DS` RRset is signed; the `NS` beside it
  and glue at or below the cut are served unsigned (RFC 4035).
- The derived records are system-owned: never edited, diffed, or rolled
  back. Version listings hide signer-only serials unless `all` is requested;
  `record list --signed` (`GET /records?signed=true`) pages them after the
  user records.
