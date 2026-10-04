# Docker Compose

Two compose files ship in `examples/`: one for a single Docker host and one for
Docker Swarm. Both set Bindizr options through environment variables rather
than a configuration file — see
[Configuration](../configuration.md#environment-variables) for the mapping.

## 1. Start the stack

Clone the repository and run the commands from its root:

```bash
git clone https://github.com/kweonminsung/bindizr.git
cd bindizr
```

`examples/compose/docker-compose.yml` builds Bindizr from the working tree and
runs it with PostgreSQL and two BIND secondaries behind a dnsdist load
balancer:

```bash
docker compose -f examples/compose/docker-compose.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, Bindizr's own DNS
`5300`, the BIND replicas `1053` and `1054`. API authentication is off in this
stack, and unsigned dynamic updates are accepted. Use it on an isolated
development host. On arm64, add `-f examples/compose/docker-compose.arm.yml`
before `up` to select the BIND image for that architecture.

## 2. Register the secondaries

The CLI has no remote mode; it runs inside the container through `exec`.
Register the two BIND replicas by their service names, so they receive NOTIFY
and may pull zones — see [Secondaries](../cli/secondaries.md):

```bash
docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr secondary create bind9-1 --address bind9-1
docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr secondary create bind9-2 --address bind9-2
```

## 3. Create a zone

Create a zone and add a record to look up. Zone creation includes an apex
`NS` record naming `--mname`:

```bash
docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
docker compose -f examples/compose/docker-compose.yml exec bindizr \
  bindizr record create example.com www --type A --value 192.0.2.1
```

Bindizr notifies both BIND replicas after each change.
Run `bindizr doctor` and `bindizr zone status example.com` through the same
`exec` command to check that they have caught up.

## 4. Query it

dnsdist on `127.0.0.1:53` spreads queries over the two replicas:

```bash
dig @127.0.0.1 www.example.com A +short
# Expected answer: 192.0.2.1
```

With authentication off, the HTTP API takes requests without a token:

```bash
curl http://127.0.0.1:8000/zones
```

## Docker Swarm

`examples/swarm/docker-compose.yml` runs the published image with BIND as a
global service, one replica per node on host-mode port 53, and PostgreSQL,
using Docker configs for the BIND configuration:

```bash
docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

The CLI runs in the `bindizr` service's container, through `docker exec` on
the node that runs it. Register the BIND service there as one secondary under
its `tasks.bind9` name, which resolves to every replica, so NOTIFY reaches
them all and each may transfer:

```bash
docker exec <bindizr-container> bindizr secondary create bind9 --address tasks.bind9
```

## Using a different database

Both examples select the bundled PostgreSQL service through
`BINDIZR_DATABASE_TYPE` and `BINDIZR_DATABASE_URL`. To switch databases, edit
those settings and remove Bindizr's `depends_on: postgres` entry where present.
Remove the unused PostgreSQL service after confirming the new database works.

- **MySQL** — `BINDIZR_DATABASE_TYPE=mysql`, with `BINDIZR_DATABASE_URL`
  pointing at your server.
- **SQLite** — `BINDIZR_DATABASE_TYPE=sqlite`, with `BINDIZR_DATABASE_SQLITE_FILE_PATH`
  for the path; `BINDIZR_DATABASE_URL` is silently ignored. The image already
  defaults to `/var/lib/bindizr/bindizr.db` inside the `bindizr-data` volume.
