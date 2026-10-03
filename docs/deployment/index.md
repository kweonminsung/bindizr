# Deployment Options

Choose a deployment method below. Each walkthrough covers starting Bindizr,
connecting a secondary, and querying your first zone with `dig`.

| Method | Use it when | Databases as shipped |
| --- | --- | --- |
| [Kubernetes](kubernetes.md) | Running on a cluster, through the Helm chart, with BIND secondaries as pods | MySQL, PostgreSQL |
| [Docker Compose](docker-compose.md) | Trying the whole stack on one Docker host | PostgreSQL |
| [Docker Swarm](docker-compose.md#docker-swarm) | Running a containerized stack across a Swarm | PostgreSQL |
| [Manual Installation](manual.md) | Running on a VM or bare-metal host from a `.deb` / `.rpm` | SQLite, MySQL, PostgreSQL |

To build the binary yourself, see [Building from Source](source.md).

## How the pieces fit

Bindizr stores zones and sends them to **secondary** name servers by AXFR
(whole zones) or IXFR (changes). The secondaries answer client queries;
use their hostnames in your zones' `NS` records.

Bindizr's **catalog zone** lists the zones each secondary should serve.
Creating or deleting a zone updates that list automatically.
[Secondary Servers](../secondaries/index.md) covers the setup.

Zones already served by another name server move over without exporting files
by hand — see [Migrating an Existing Primary](migrating.md).

Every deployment reads the same set of options — see
[Configuration](../configuration.md) for the full reference, including the
environment-variable form used by the container deployments.
