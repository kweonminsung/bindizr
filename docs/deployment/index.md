# Deployment Options

Bindizr can be deployed on Kubernetes, with Docker Compose or Swarm, or as a
package on a host. Every walkthrough ends the same way: Bindizr running
next to a name server that answers for it, and a zone you created answering
a `dig`.

| Method | Use it when | Databases as shipped |
| --- | --- | --- |
| [Kubernetes](kubernetes.md) | Running on a cluster, through the Helm chart, with BIND secondaries as pods | MySQL, PostgreSQL |
| [Docker Compose](docker-compose.md) | Trying the whole stack on one Docker host | PostgreSQL |
| [Docker Swarm](docker-compose.md#docker-swarm) | Running a containerized stack across a Swarm | PostgreSQL |
| [Manual Installation](manual.md) | Running on a VM or bare-metal host from a `.deb` / `.rpm` | SQLite, MySQL, PostgreSQL |

The binary the packages carry can also be built from source, for a host they
do not cover — see [Building from Source](source.md).

## How the pieces fit

Bindizr does not answer DNS queries from clients. It stores zones in a
database, lets you manage them over an HTTP API and a CLI, and serves them
to one or more **secondary** name servers by zone transfer, the standard way
a primary hands zones to a secondary (AXFR sends a whole zone, IXFR only the
changes). The secondary — BIND, Knot DNS, NSD, or PowerDNS — answers the
queries, so it is the server the zones' `NS` records point at.

The secondary learns which zones exist from Bindizr's **catalog zone**
(RFC 9432): a zone Bindizr serves whose records list the other zones. Create
or delete a zone in Bindizr and the secondary picks it up on its own, with
no configuration change. [Secondary Servers](../secondaries/index.md) covers
setting one up.

Zones already served by another name server move over without exporting files
by hand — see [Migrating an Existing Primary](migrating.md).

Every deployment reads the same set of options — see
[Configuration](../configuration.md) for the full reference, including the
environment-variable form used by the container deployments.
