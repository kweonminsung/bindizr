# Advanced DNSSEC

What a [signed zone](index.md) looks like from the outside: what
gets signed, and how the records Bindizr derives behave in listings and
history.

- At a delegation only the child's `DS` records are signed; the `NS` records
  beside them and glue at or below the cut are served unsigned (RFC 4035).
- The derived records are system-owned: never edited, diffed, or rolled
  back. Version listings hide past serials containing only derived changes
  unless `--include-signer-only-versions` is passed to `zone version list`
  (`include_signer_only_versions=true` over HTTP). The current serial and
  serials without journal entries remain visible;
  `record list --include-dnssec` (`GET /records?include_dnssec=true`) pages them after the
  user records.
