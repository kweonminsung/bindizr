# Troubleshooting

`bindizr doctor` is the first stop: each line names one piece of the
installation, and it runs the database and port checks itself when the daemon
is down. The tables below pair the messages you will meet with what to do.

## The daemon

| Symptom | Where | Fix |
| --- | --- | --- |
| `Is the bindizr daemon running?` | any CLI command | Start it: `sudo systemctl start bindizr`, or `bindizr start` in the foreground. `journalctl -u bindizr` shows why a start failed. |
| `Bindizr is already running.` | `bindizr start` | Another daemon holds the control socket. Stop it with `bindizr stop` or `systemctl stop bindizr` rather than starting a second one. |
| `Permission denied on the daemon socket` | any CLI command | The socket is owner-only. Run the CLI as the daemon's user: `sudo bindizr …` on a package install, `docker exec` / `kubectl exec` in a container. |
| `unknown field \`…\`` | start, `config check` | A mistyped configuration key; the message lists the keys the section accepts. |
| `… connection failed (check database.mysql.url)` | start, doctor | The key the message names is wrong, or the database is unreachable from this host. `bindizr doctor` repeats the connection without the daemon. |
| `Address already in use` / `DNS port in use` | start, doctor | The secondary on the same host holds the port. Keep `dns.listen_port` off 53 (the package default is 5300) and point the secondary's catalog zone at that port. |
| `these settings are fixed while bindizr runs` | `config reload` | `[api]`, `[database]`, and the DNS listen address and port need a restart: `sudo systemctl restart bindizr`. |

## Secondaries

| Symptom | Where | Fix |
| --- | --- | --- |
| A secondary never picks up a new zone | `bindizr zone status`, the secondary's log | A secondary learns zones from `catalog.bindizr`. Check that it reached the catalog serial `bindizr doctor` reports, then its log for the catalog transfer; `bindizr zone notify` resends NOTIFY for every zone. [Secondary Servers](secondaries/index.md) has each server's command for inspecting a zone. |
| `Secondary unreachable` | doctor, `zone status` | The address in `dns.secondary_addrs` is wrong, or a firewall sits between bindizr and the secondary. |
| `Secondary out of sync` | doctor, `zone status` | The secondary has not pulled the current serial. BIND's log names the reason it refused or deferred the transfer. |
| `NOTIFY rejected` | doctor | BIND's `allow-notify` does not admit bindizr's address; the setup script adds `allow-notify { any; }`. |
| A secondary's transfer is `REFUSED` | BIND's log, `bindizr_xfr_total{result="refused"}` | The secondary is not listed in `dns.secondary_addrs`, or it signs with a key bindizr does not know — see [TSIG Keys](cli/tsig-keys.md#signing-zone-transfers). |

## The API

| Symptom | Fix |
| --- | --- |
| Every request answers `401` | Authentication is on and no valid token was sent. Create the first one on the daemon host: `sudo bindizr token create admin --global`; `bindizr status` shows whether authentication is on. |
| `404` for a zone that exists | The token is scoped and not granted that zone: `bindizr token grant <TOKEN> <zone>` — see [API Tokens](cli/tokens.md). |
| `403` on a write | The write falls outside the token's grant (its record-name pattern, types, or `--read-only`). |
| `503` from `/health` | The database did not answer within the probe's timeout; see the database row above. |

## Dynamic updates and DNSSEC

| Symptom | Fix |
| --- | --- |
| `unsigned NSUPDATE refused` | Sign the request with a TSIG key bindizr knows and that is granted the zone — see [Dynamic Updates](cli/nsupdate.md). Turning off `dns.nsupdate_tsig_required` is for testing only. |
| `dnssec disable` refused | The parent still serves the zone's DS, or could not be asked. Remove the DS at the parent and wait out its TTL, or pass `--skip-ds-check` when the parent is known to be clear — see [DNSSEC](dnssec.md). |
