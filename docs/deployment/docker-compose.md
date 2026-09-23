# Docker Compose

Two compose files ship in `examples/`: one for a single Docker host and one for
Docker Swarm. Both set Bindizr options through environment variables rather
than a configuration file — see
[Configuration](../configuration.md#environment-variables) for the mapping.

## One host: Docker Compose

`examples/compose/docker-compose.yml` builds Bindizr from the working tree and
runs it with PostgreSQL and two BIND secondaries behind a dnsdist load
balancer:

```bash
$ docker compose -f examples/compose/docker-compose.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, Bindizr's own DNS
`5300`, the BIND replicas `1053` and `1054`. API authentication is off in this
stack, which suits a laptop and nothing reachable by others. On arm64 hosts
add `-f examples/compose/docker-compose.arm.yml`, which swaps the amd64-only
ISC BIND image.

### Create a zone and query it

The CLI has no remote mode; it runs inside the container through `exec`.
Create a zone, give it its `NS` record (BIND will not load a zone without
one), and add a record to look up:

```bash
$ docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
$ docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr record create example.com @ --type NS --value ns1.example.com
$ docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr record create example.com www --type A --value 192.0.2.1
```

Bindizr notifies both BIND replicas after each change and they pull the
zone within a second. dnsdist on `127.0.0.1:53` spreads queries over them:

```bash
$ dig @127.0.0.1 www.example.com A +short
192.0.2.1
```

With authentication off, the HTTP API takes requests without a token:

```bash
$ curl http://127.0.0.1:8000/zones
```

`bindizr doctor` and `bindizr zone status example.com`, run the same way
through `exec`, show whether each replica has caught up.

## Docker Swarm

`examples/swarm/docker-compose.yml` runs the published image with BIND as a
global service, one replica per node on host-mode port 53, and PostgreSQL,
using Docker configs for the BIND configuration:

```bash
$ docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

The CLI runs in the `bindizr` service's container, through `docker exec` on
the node that runs it.

## Using a different database

Both stacks are PostgreSQL-only: `BINDIZR_DATABASE_TYPE` and
`BINDIZR_DATABASE_URL` are pinned to the bundled `postgres` service. Edit them
in the compose file to switch, and drop `postgres` and its volume once unused.

- **MySQL** — `BINDIZR_DATABASE_TYPE=mysql`, with `BINDIZR_DATABASE_URL`
  pointing at your server.
- **SQLite** — `BINDIZR_DATABASE_TYPE=sqlite`, with `BINDIZR_DATABASE_SQLITE_FILE_PATH`
  for the path; `BINDIZR_DATABASE_URL` is silently ignored. The image already
  defaults to `/var/lib/bindizr/bindizr.db` inside the `bindizr-data` volume.
