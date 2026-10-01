# Advanced Configuration

Two [configuration](../configuration.md) settings trade latency or memory for
throughput.

## Batching NOTIFY

`dns.notify.batch_ms` decides what happens on the write path once a change is
committed.

`0` (the default)
:   Every change sends its own NOTIFY before the write is answered. Lowest
    latency to visibility.

a window in milliseconds
:   The write is answered at commit; changes to the same zone inside the
    window collapse into one NOTIFY, sent from a queue. Worth it when many
    records change at once.

## Sizing the transfer cache

`dns.transfer_cache.max_records` counts records, not bytes, so converting a
memory budget takes one step. A cached record costs roughly:

| Record | Cost |
| --- | --- |
| `A` with a short name | 130 bytes |
| `TXT` with a 255-byte value | 375 bytes |
| `TXT` carrying a DKIM key | 860 bytes |

The default of 500,000 records is about 64 MiB of plain address records, more
where large `TXT` values or a signed zone's derived records dominate. Watch
`bindizr_zone_cache_records` against the limit and
`bindizr_zone_cache_evictions_total`: evictions rising beside a low hit ratio in
`bindizr_zone_cache_lookups_total` mean the working set does not fit.
