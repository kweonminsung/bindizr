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

The batching delay is capped at the zone's SOA REFRESH (RFC 1996, Section 4.3),
measured from enqueue time. The generated catalog uses a 3600-second REFRESH.
Later writes can shorten a pending window but cannot extend it; jobs delayed
by an earlier send do not start a new window. Collecting the next batch does
not wait for earlier acknowledgements. Shutdown flushes queued changes and
waits for outstanding transactions.

Any matching response ends a NOTIFY transaction, whatever its code (RFC 1996,
Sections 3.6 and 4.8): a validated `NOTIMP` completes it and is logged as an
unsupported capability (Section 3.12); another error code is reported without
retransmission. Only silence retains the configured retries, and an ICMP port
unreachable error ends the transaction as well. A retransmission repeats the
same message from the same socket, so an acknowledgement that arrives after
`timeout_secs` still counts. A signed NOTIFY ignores an unsigned reply or one
that fails verification, logging it at `warn` while it keeps waiting (RFC
8945, Section 5.4); the key name, secret or algorithm the secondary holds is
then what to check. `zone notify` for all zones and `POST /notify` send the
zones concurrently. Sixteen zones may prepare keys and addresses at a time;
acknowledgement waits do not hold those slots. Active transactions to the
same address share a UDP socket, with distinct IDs assigned before signing.

## Sizing the transfer cache

`dns.transfer.cache_max_records` limits the record count. Approximate memory
costs depend on the record contents:

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
