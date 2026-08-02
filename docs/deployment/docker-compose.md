# Docker Compose

Use the default `docker-compose.yml` with Docker Swarm for a containerized
Bindizr deployment.

```bash
$ docker stack deploy -c docker-compose.yml bindizr
```

The stack runs Bindizr, PostgreSQL, and BIND9 on an overlay network, using
Docker configs for BIND9 configuration.

The compose files set Bindizr options through environment variables rather than
a config file — see [Configuration](../configuration.md#environment-variables)
for the mapping.

## Using a different database

The stack is PostgreSQL-only: `BINDIZR_DATABASE_TYPE` and
`BINDIZR_DATABASE_URL` are pinned to the bundled `postgres` service. Edit them
in the compose file to switch, and drop `postgres` and its volume once unused.

- **MySQL** — `BINDIZR_DATABASE_TYPE=mysql`, with `BINDIZR_DATABASE_URL`
  pointing at your server.
- **SQLite** — `BINDIZR_DATABASE_TYPE=sqlite`, with `BINDIZR_SQLITE_FILE_PATH`
  for the path; `BINDIZR_DATABASE_URL` is silently ignored. The image already
  defaults to `/var/lib/bindizr/bindizr.db` inside the `bindizr-data` volume.
