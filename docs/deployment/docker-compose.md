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
balancer. On amd64:

```bash
docker compose -f examples/compose/docker-compose.yml up -d --build
```

On arm64, select the BIND image for that architecture:

```bash
docker compose -f examples/compose/docker-compose.yml \
  -f examples/compose/docker-compose.arm.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, Bindizr's own DNS
`5300`, the BIND replicas `1053` and `1054`. API authentication is off in this
stack, and unsigned dynamic updates are accepted. Use it on an isolated
development host.

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
using Docker configs for BIND configuration and a Docker secret for its
transfer key. Run these commands from the repository root on a Swarm manager
(`docker swarm init` creates a single-node Swarm).

### Prepare the transfer key

BIND connects to Bindizr's service VIP so primary task replacement keeps the
same address. Swarm can translate the transfer's source IP, so transfers use
TSIG authentication instead of relying on the registered secondary addresses.
Create the secret once before deploying; it is mounted in both services:

```bash
printf 'key "swarm-xfr" {\n  algorithm hmac-sha256;\n  secret "%s";\n};\n' \
  "$(openssl rand -base64 32)" | docker secret create bindizr_xfr_key -
```

### Start the services

On amd64:

```bash
docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

On an arm64 Swarm, build the BIND image on **each node** first. Swarm does not
build images, and its startup script needs a shell that the Compose example's
Ubuntu BIND image does not include:

```bash
docker build -t bindizr-swarm-bind9:local examples/swarm/bind9
```

Then deploy from the manager with that image. `--resolve-image never`
uses the locally built image without looking it up in a registry:

```bash
BIND9_IMAGE=bindizr-swarm-bind9:local docker stack deploy --resolve-image never \
  -c examples/swarm/docker-compose.yml bindizr
```

### Authorize transfers and register BIND

Find the node running Bindizr with `docker service ps bindizr_bindizr`. On
that node, wait for `bindizr status` to succeed, then run the CLI through its
container. The transfer role needs `zone:transfer` in all zones, including the
catalog; the TSIG secret is read from the mounted file:

```bash
BINDIZR_CONTAINER=$(docker ps -q --filter label=com.docker.swarm.service.name=bindizr_bindizr)
docker exec "$BINDIZR_CONTAINER" bindizr status
docker exec "$BINDIZR_CONTAINER" bindizr role create swarm-secondaries
docker exec "$BINDIZR_CONTAINER" bindizr role grant swarm-secondaries --actions zone:transfer
docker exec "$BINDIZR_CONTAINER" sh -ec '
  bindizr tsig-key create swarm-xfr --role swarm-secondaries \
    --secret "$(awk -F\" "/secret/ {print \$2}" /run/secrets/bindizr-xfr.key)"
' > /dev/null
docker exec "$BINDIZR_CONTAINER" bindizr secondary create bind9 --address tasks.bind9
```

`tasks.bind9` resolves to the BIND replicas so NOTIFY reaches each one.
Before the key is registered, BIND may log refused transfers; it retries
after registration. These setup commands run once per fresh database.

### Create and query a zone

```bash
docker exec "$BINDIZR_CONTAINER" bindizr zone create example.com \
  --mname ns1.example.com --rname admin@example.com
docker exec "$BINDIZR_CONTAINER" bindizr record create example.com www --type A --value 192.0.2.1
```

Wait for the catalog and member zone to transfer, then check their status and
query any Swarm node:

```bash
docker exec "$BINDIZR_CONTAINER" bindizr doctor
docker exec "$BINDIZR_CONTAINER" bindizr zone status example.com
dig @<swarm-node-address> www.example.com A +short
# Expected answer: 192.0.2.1
```

After task replacement, find the current container again before using `exec`.
BIND retries failed transfers at intervals of at most 60 seconds while the
replacement primary becomes reachable.
The database and zone volumes are local to each node; keep stateful services
on their data-bearing nodes or configure shared storage for rescheduling.

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
