# Key Rollover

Rollover replaces a key without breaking validation (RFC 7583 pre-publish):

```sh
bindizr dnssec rollover start example.com            # CSK zones
bindizr dnssec rollover start example.com --role zsk # split-key zones
```

`start` pre-publishes a replacement with the same algorithm: it joins the
`DNSKEY` records (and, for CSK/KSK, the CDS/CDNSKEY records) but signs nothing
yet, for as long as a resolver can still hold a `DNSKEY` answer without it:
the zone's TTL, plus the SOA refresh for a secondary that missed the NOTIFY to
catch up (RFC 7583, Section 3.2.1). Then:

- **ZSK:** the scheduler promotes the key after the publish wait. Set the
  policy's `zsk_lifetime_days` to also start ZSK rollovers automatically;
  the default of 0 disables automatic starts.
- **CSK / KSK:** publish the new DS at the parent, or let a parent that
  processes CDS do so. After the publish wait, the scheduler promotes the
  key once every configured parent server serves its DS.

To request CSK/KSK promotion without waiting for the next scheduler pass:

```sh
bindizr dnssec rollover ds-seen example.com
```

This applies the same wait and DS checks. `bindizr dnssec check-ds example.com`
shows the parent's DS and the remaining wait. `--skip-ds-check` bypasses the
parent query; `--skip-holddown` bypasses the publish wait and can break
validation for resolvers still caching the old DNSKEY records. Reserve those
overrides for a recovery procedure where you have checked the consequences.

A retired key stays published until what points at it has drained from
caches: the longest TTL it signed, and for a KSK or CSK the parent's DS TTL,
read from the same answer that confirmed the promotion, plus the SOA refresh
again. Then the scheduler removes it. `status` shows every key's state
(`published`/`active`/`retired`) throughout.

## Algorithm rollover

An **algorithm rollover** (RFC 6840, Section 5.11) is started by moving the
zone to a policy of the new algorithm (`dnssec set --policy`): every key is
replaced with one of the new algorithm and the zone is double-signed — both
algorithms cover all data — until promotion and cache expiry allow the old keys to be removed.
