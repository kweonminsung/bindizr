# CLI Commands

Bindizr provides a command-line interface for managing the DNS synchronization
service, its zone data, access control (API tokens, TSIG keys), and DNSSEC.
`bindizr help` lists everything; this page covers the commands you reach for
most and points to the pages that cover the rest.

Every command except `start` and `config check` needs the daemon running
and has full control over it, so it runs as the daemon's user: `sudo bindizr
...` for a package install, or a shell inside the container for Compose and
Helm. There is no remote mode.

## Command map

| Commands | What they manage | Documented in |
|---|---|---|
| `start`, `stop`, `restart`, `status`, `doctor`, `config` | The daemon and its configuration | this page |
| `completion`, `man` | The shell completion scripts and the man page | this page |
| `zone`, `record` | Zone data: CRUD, import/export, versions, NOTIFY, secondary status | [Zones and Records](zones.md) |
| `token` | API tokens and the zones each is granted over HTTP | [API Tokens](tokens.md) |
| `tsig-key` | TSIG keys and the zones each is granted for nsupdate | [TSIG Keys](tsig-keys.md), [Dynamic Updates](nsupdate.md) |
| `dnssec-policy`, `dnssec` | Signing-parameter bundles and each zone's signing state | [DNSSEC](../dnssec/index.md) |

Every command that reports something prints a table and takes `-o json` or
`-o yaml`, whose payload is the same body the HTTP API returns; `delete` and
the one-shot actions print a message. `zone export`, `dnssec keys export`, and
`tsig-key export` print paste-ready text instead, so none of the three takes
`-o`. A command's result goes to stdout and its diagnostics to stderr, so a
pipeline keeps the result clean.

## Service

```bash
# Start bindizr on foreground
$ bindizr start

# Start with a custom configuration file. `start`, `doctor`, and `config check`
# all take `-c` and fall back to $BINDIZR_CONFIG_PATH
$ bindizr start -c <FILE>

# Stop the running daemon, or restart it in place
$ bindizr stop
$ bindizr restart

# Whether the daemon runs, where it listens, its database and zone count, and its
# secondaries. Exits non-zero when the database does not answer, so a health
# check can branch on it
$ bindizr status

# Check the installation end to end; without a daemon it checks the database, the
# listen ports, and BIND's catalog setup itself
$ bindizr doctor

# Validate a configuration file without starting bindizr (defaults to /etc/bindizr/bindizr.conf.toml)
$ bindizr config check [-c <FILE>]

# Show the configuration loaded by the running daemon, or one value by dotted key
$ bindizr config list
$ bindizr config get dns.secondary_addrs

# Re-read the configuration file without restarting (`systemctl reload bindizr` or SIGHUP does the same)
$ bindizr config reload

# doctor also answers as one JSON document, for a cron job or CI check
$ bindizr doctor -o json
```

## Completions and the man page

A package install puts both in place already. Elsewhere the binary prints
them, generated from the same command it parses with:

```bash
# Shell completion: bash, zsh, fish, elvish, or powershell
$ bindizr completion bash | sudo tee /usr/share/bash-completion/completions/bindizr
$ bindizr completion zsh  | sudo tee /usr/share/zsh/site-functions/_bindizr
$ bindizr completion fish > ~/.config/fish/completions/bindizr.fish

# Man page
$ bindizr man | sudo tee /usr/share/man/man1/bindizr.1 > /dev/null
```

## Exit codes

A failure exits with the class of the error, so a script can branch on it
without parsing the message.

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Failure, including invalid input |
| `2` | Usage error, such as an unknown command or a missing argument |
| `3` | Not found: no such zone, record, token, version, key, or policy |
| `4` | Conflict: the name is taken, or the object is in use or in the wrong state |
| `5` | Denied: the token is missing, invalid, or lacks a grant |
| `6` | The configuration file is unusable, so running the same command again changes nothing |
| `7` | Unavailable: the daemon is not running, so the command never reached it |
