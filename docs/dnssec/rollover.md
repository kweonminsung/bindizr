# Key Rollover

Rollover replaces a key without breaking validation (RFC 7583 pre-publish):

```sh
bindizr dnssec rollover start example.com            # CSK zones
bindizr dnssec rollover start example.com --role zsk # split-key zones
```

`start` pre-publishes a replacement with the same algorithm: it joins the
`DNSKEY` records (and, for CSK/KSK, the CDS/CDNSKEY records) but signs nothing
yet, for as long as a resolver can still hold a `DNSKEY` answer without it —
the zone's TTL. Then:

- **ZSK** — no parent involvement: the scheduler promotes it automatically
  after the wait. With the [policy's](policies.md) `zsk_lifetime_days` set (0, the default,
  disables it), the scheduler also *starts* ZSK rollovers on its own once the
  active ZSK outlives that many days, making split-key ZSK rotation fully
  hands-off. CSKs are never auto-*started* — a new DS has to reach the parent
  first — but the scheduler finishes them, as below.
- **CSK / KSK** — the new DS has to reach the parent. Publish it there, or
  let a parent that consumes CDS install it itself; either way the scheduler
  asks the zone's parent name servers on every pass and promotes the key once
  all of them serve its DS. Nothing to run.

  To finish it now instead of waiting for the next pass:

  ```sh
  bindizr dnssec rollover ds-seen example.com
  ```

  It refuses before the publish wait passes and while the parent's
  name servers do not serve the new key's DS — the same two conditions the
  scheduler applies. The overrides are what the scheduler has no way to
  express: `--skip-ds-check` takes your word on the DS, for a host that
  cannot reach the parent at all, and `--skip-holddown` promotes a
  compromised key before the wait ends, at the cost of validation failures
  at resolvers still caching the previous keys. `bindizr dnssec check-ds`
  shows which keys' DS the parent serves and when the wait ends.

A retired key stays published until what points at it has drained from
caches: the longest TTL it signed, and for a KSK or CSK the parent's DS TTL,
read from the same answer that confirmed the promotion. Then the scheduler
removes it. `status` shows every key's state
(`published`/`active`/`retired`) throughout.

## Algorithm rollover

An **algorithm rollover** (RFC 6840, Section 5.11) is started by moving the
zone to a policy of the new algorithm (`dnssec set --policy`): every key is
replaced with one of the new algorithm and the zone is double-signed — both
algorithms cover all data — until the old keys leave together after
`ds-seen`.
