# DNSSEC Policies

How a zone is signed is described by a **DNSSEC policy**, a named bundle of
signing parameters that zones reference — the same shape as BIND's
`dnssec-policy` and Knot's `policy`. A `default` policy is seeded at
startup; create others when zones need a different algorithm, denial mode,
key layout, or timing.

```sh
bindizr dnssec-policy list
bindizr dnssec-policy create strict --algorithm ed25519 --denial nsec3 \
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
    signing.

`denial`
:   `nsec3` (default, RFC 9276 parameters) or `nsec`. NSEC lets anyone walk
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

The algorithm, denial mode, and key layout are fixed once a policy exists
(move a zone to another policy to change them);
the timing fields can be edited in place and apply to every zone under the
policy from its next signing pass or scheduler scan. A policy in use
cannot be deleted, and neither can `default`: edit it to change the
installation's defaults.

## Signature refresh

Signatures are valid for the policy's `signature_validity_days` (default 14)
and renewed once fewer than `signature_refresh_days` (default 5) remain; the
scheduler pass handles this with no operator action. Every instance runs the
whole pass, so a deployment of several can set
`dns.scheduler_interval_secs = 0` on all but one — at least one must keep
it, or signatures expire. `bindizr dnssec
sign example.com` forces a full re-sign if stored signatures are ever
doubted.

To give some zones different timing, create a policy with the values you
want and move them to it with `dnssec set --policy`; editing a policy
with `dnssec-policy update` changes every zone under it from the next
signing pass or scheduler scan. `dnssec status` reports the zone's
policy and its values.
