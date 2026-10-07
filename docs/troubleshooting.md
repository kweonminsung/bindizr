# Troubleshooting

Start with `bindizr doctor`. It checks the database, listeners, and secondary
catalog synchronization, and can diagnose startup problems while the daemon
is stopped. Use `bindizr secondary check <name>` to investigate one server.
On a package install, run these commands with `sudo`.

## The daemon

| Symptom | Where | Fix |
| --- | --- | --- |
| `Is the bindizr daemon running?` | any CLI command | Start it: `sudo systemctl start bindizr`, or `bindizr start` in the foreground. `journalctl -u bindizr` shows why a start failed. |
| `Bindizr is already running` | `bindizr start` | Another daemon is running. Stop it with `bindizr stop` or `systemctl stop bindizr` rather than starting a second one. |
| `Permission denied on the daemon socket` | any CLI command | Run the CLI as the daemon's user: `sudo bindizr …` on a package install, `docker exec` / `kubectl exec` in a container. |
| `The daemon at '/tmp/bindizr/bindizr.sock' runs as uid …` | any CLI command | Run the CLI as the daemon's user or root. Remove a stale socket only after confirming its daemon has stopped. |
| `unknown field \`…\`` | start, `config check` | A mistyped configuration key; the message lists the keys the section accepts. |
| `… connection failed (check database.mysql.url)` | start, doctor | The key the message names is wrong, or the database is unreachable from this host. `bindizr doctor` repeats the connection without the daemon. |
| `Address already in use` / `DNS port in use` | start, doctor | The secondary on the same host holds the port. Keep `dns.listen_port` off 53 (the package default is 5300) and point the secondary's catalog zone at that port. |
| `these settings are fixed while bindizr runs` | `config reload` | `[api]`, `[database]`, the DNS listen address and port, and the catalog name require a restart. See [Reloading](configuration.md#reloading). |
| `duplicate key value violates unique constraint "pg_type_typname_nsp_index"` | first start on PostgreSQL | Two replicas tried to initialize the schema at once. Let the failed replica restart after initialization finishes. If failures continue, inspect its startup and database logs. |

## Secondaries

| Symptom | Where | Fix |
| --- | --- | --- |
| A secondary never picks up a new zone | `zone status`, secondary logs | Run `bindizr secondary list` and `bindizr secondary check <name>`. Confirm registration and the catalog configuration in [Secondary Servers](secondaries/index.md), then retry with `bindizr zone notify`. |
| Catalog is in sync, but a zone returns `SERVFAIL` | `zone status`, secondary logs | Check `bindizr secondary transfers <name> --zone <zone>`. A member transfer or zone load can fail independently of the catalog. Confirm the zone has apex NS records; BIND logs `has no NS records` when they are missing. |
| `Secondary unreachable` | doctor, `zone status` | The address it was registered with is wrong, or a firewall sits between Bindizr and the secondary; `bindizr secondary check <name>` shows what the address resolves to and what the server answered. |
| `Secondary out of sync` | doctor, `zone status` | The secondary has not pulled the current serial: the catalog zone's for `doctor`, a member zone's for `zone status`, so the two can disagree for the moment a transfer takes. Persisting, BIND's log names the reason it refused or deferred the transfer. |
| `NOTIFY rejected` | doctor | Allow Bindizr's source address in the secondary's NOTIFY ACL. If the secondary requires TSIG, register it with the matching `--notify-key`; see [Signed NOTIFY](cli/secondaries.md#signed-notify). |
| A secondary's transfer is `REFUSED` | BIND's log, `bindizr_xfr_total{result="refused"}` | The secondary is not registered or is disabled (`bindizr secondary list`), its address changed since it was registered (register it by [hostname](cli/secondaries.md#addresses) instead), or it signs with a key Bindizr does not know or whose role lacks `zone:transfer` for the zone — see [Signing zone transfers](cli/advanced.md#signing-zone-transfers). |
| A transfer over TLS is `REFUSED` or its handshake fails | Bindizr's log, the secondary's log | Over TLS the secondary must be registered *and* sign with a key. A handshake fails when the certificate lacks the name the secondary checks, or the secondary offers TLS 1.2 or an ALPN other than `dot`; see [Transfers over TLS](secondaries/index.md#transfers-over-tls). |

## The HTTP API

| Symptom | Fix |
| --- | --- |
| Every request answers `401` | Authentication is on and no valid token was sent. Create the first one on the daemon host: `sudo bindizr token create admin --role admin`; `bindizr status` shows whether authentication is on. |
| `404` for a zone that exists | No grant of the token's role reaches that zone: `bindizr role grant <ROLE> --zone <zone> --actions …` — see [Access Control](cli/access-control.md). `GET /tokens/self/grants` lists what the token holds. |
| `403` on a write | The zone is visible but no grant of the token's role covers the operation: the action is missing, or the record falls outside its name pattern or types. See [what an operation needs](cli/advanced.md#what-an-operation-needs). |
| `503` from `/health` | The database did not answer within the probe's timeout; see the database row above. |

## Dynamic updates and DNSSEC

| Symptom | Fix |
| --- | --- |
| `unsigned NSUPDATE refused` | Sign the request with a TSIG key Bindizr knows, whose role covers the records the update touches — see [Dynamic Updates](cli/nsupdate.md). Turning off `dns.nsupdate.tsig_required` is for testing only. |
| `dnssec disable` refused | The parent still serves the zone's DS, or could not be asked. Remove the DS at the parent and wait out its TTL, or pass `--skip-ds-check` when the parent is known to be clear — see [DNSSEC](dnssec/index.md). |
