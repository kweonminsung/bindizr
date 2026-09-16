# Deployment Options

Bindizr can be deployed with Helm, Docker Compose or Swarm, or a manual
package-based setup.

| Method | Use it when | Databases as shipped |
| --- | --- | --- |
| [Helm](helm.md) | Running on Kubernetes, with BIND9 secondaries as pods | MySQL, PostgreSQL |
| [Docker Compose](docker-compose.md#one-host-docker-compose) | Trying the whole stack on one Docker host | PostgreSQL |
| [Docker Swarm](docker-compose.md#docker-swarm) | Running a containerized stack across a Swarm | PostgreSQL |
| [Manual Installation](manual.md) | Running on a VM or bare-metal host from a `.deb` / `.rpm` | SQLite, MySQL, PostgreSQL |

Whichever you pick, the shape is the same: Bindizr owns the zone data and serves
it over AXFR/IXFR, and one or more BIND9 secondaries discover zones through the
catalog zone and answer client queries.

Every deployment reads the same set of options — see
[Configuration](../configuration.md) for the full reference, including the
environment-variable form used by the container deployments.
