# Docker Compose

Two compose files ship in `examples/`: one for a single Docker host and one for
Docker Swarm. Both set Bindizr options through environment variables rather
than a config file — see
[Configuration](../configuration.md#environment-variables) for the mapping.

## One host: Docker Compose

`examples/compose/docker-compose.yml` builds Bindizr from the working tree and
runs it with PostgreSQL and two BIND9 secondaries behind a dnsdist load
balancer:

```bash
$ docker compose -f examples/compose/docker-compose.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, Bindizr's own DNS
`5300`, the BIND9 replicas `1053` and `1054`. API authentication is off in this
stack. On arm64 hosts add `-f examples/compose/docker-compose.arm.yml`, which
swaps the amd64-only ISC BIND9 image.

## Docker Swarm

`examples/swarm/docker-compose.yml` runs the published image with BIND9 as a
global service, one replica per node on host-mode port 53, and PostgreSQL,
using Docker configs for the BIND9 configuration:

```bash
$ docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

## Using a different database

Both stacks are PostgreSQL-only: `BINDIZR_DATABASE_TYPE` and
`BINDIZR_DATABASE_URL` are pinned to the bundled `postgres` service. Edit them
in the compose file to switch, and drop `postgres` and its volume once unused.

- **MySQL** — `BINDIZR_DATABASE_TYPE=mysql`, with `BINDIZR_DATABASE_URL`
  pointing at your server.
- **SQLite** — `BINDIZR_DATABASE_TYPE=sqlite`, with `BINDIZR_DATABASE_SQLITE_FILE_PATH`
  for the path; `BINDIZR_DATABASE_URL` is silently ignored. The image already
  defaults to `/var/lib/bindizr/bindizr.db` inside the `bindizr-data` volume.
