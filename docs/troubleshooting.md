# Troubleshooting

`bindizr doctor` is the first stop: each line names one piece of the
installation, and it runs the database and port checks itself when the daemon
is down. The tables below pair the messages you will meet with what to do.

## The daemon

| Symptom | Where | Fix |
| --- | --- | --- |
| `Is the bindizr daemon running?` | any CLI command | Start it: `sudo systemctl start bindizr`, or `bindizr start` in the foreground. `journalctl -u bindizr` shows why a start failed. |
| `Bindizr is already running.` | `bindizr start` | Another daemon is running. Stop it with `bindizr stop` or `systemctl stop bindizr` rather than starting a second one. |
| `Permission denied on the daemon socket` | any CLI command | Run the CLI as the daemon's user: `sudo bindizr …` on a package install, `docker exec` / `kubectl exec` in a container. |
| `The daemon at '/tmp/bindizr/bindizr.sock' runs as uid …` | any CLI command | The socket the CLI reached belongs to a daemon another user is running, or left behind. Run the CLI as that user, or remove the socket as that user. |
| `unknown field \`…\`` | start, `config check` | A mistyped configuration key; the message lists the keys the section accepts. |
| `… connection failed (check database.mysql.url)` | start, doctor | The key the message names is wrong, or the database is unreachable from this host. `bindizr doctor` repeats the connection without the daemon. |
| `Address already in use` / `DNS port in use` | start, doctor | The secondary on the same host holds the port. Keep `dns.listen_port` off 53 (the package default is 5300) and point the secondary's catalog zone at that port. |
| `these settings are fixed while bindizr runs` | `config reload` | `[api]`, `[database]`, and the DNS listen address and port need a restart: `sudo systemctl restart bindizr`. |
| `duplicate key value violates unique constraint "pg_type_typname_nsp_index"` | first start on PostgreSQL | Two replicas set up the database at once on the first start and PostgreSQL let only one create the tables; the other exits and finds them on its restart. Harmless, and gone after the first start. |

## Secondaries

| Symptom | Where | Fix |
| --- | --- | --- |
| A secondary never picks up a new zone | `bindizr zone status`, the secondary's log | A secondary learns zones from `catalog.bindizr`. Check that it reached the catalog serial `bindizr doctor` reports, then its log for the catalog transfer; `bindizr zone notify` resends NOTIFY for every zone. [Secondary Servers](secondaries/index.md) has each server's command for inspecting a zone. |
| `Secondary unreachable` | doctor, `zone status` | The address it was registered with (`bindizr secondary list`) is wrong, or a firewall sits between Bindizr and the secondary. |
| `Secondary out of sync` | doctor, `zone status` | The secondary has not pulled the current serial: the catalog zone's for `doctor`, a member zone's for `zone status`, so the two can disagree for the moment a transfer takes. Persisting, BIND's log names the reason it refused or deferred the transfer. |
| `NOTIFY rejected` | doctor | BIND's `allow-notify` does not admit Bindizr's address (the setup script adds `allow-notify { any; }`), or it requires a key the secondary was not registered with — see [Signed NOTIFY](cli/secondaries.md#signed-notify). |
| A secondary's transfer is `REFUSED` | BIND's log, `bindizr_xfr_total{result="refused"}` | The secondary is not registered or is disabled (`bindizr secondary list`), its address changed since it was registered (register it by [hostname](cli/secondaries.md#addresses) instead), or it signs with a key Bindizr does not know — see [TSIG Keys](cli/tsig-keys.md#signing-zone-transfers). |

## The HTTP API

| Symptom | Fix |
| --- | --- |
| Every request answers `401` | Authentication is on and no valid token was sent. Create the first one on the daemon host: `sudo bindizr token create admin --global`; `bindizr status` shows whether authentication is on. |
| `404` for a zone that exists | The token is scoped and not granted that zone: `bindizr token grant <TOKEN> <zone>` — see [API Tokens](cli/tokens.md). |
| `403` on a write | The write falls outside the token's grant (its record-name pattern, types, or `--read-only`). |
| `503` from `/health` | The database did not answer within the probe's timeout; see the database row above. |

## Dynamic updates and DNSSEC

| Symptom | Fix |
| --- | --- |
| `unsigned NSUPDATE refused` | Sign the request with a TSIG key Bindizr knows and that is granted the zone — see [Dynamic Updates](cli/nsupdate.md). Turning off `dns.nsupdate_tsig_required` is for testing only. |
| `dnssec disable` refused | The parent still serves the zone's DS, or could not be asked. Remove the DS at the parent and wait out its TTL, or pass `--skip-ds-check` when the parent is known to be clear — see [DNSSEC](dnssec/index.md). |
