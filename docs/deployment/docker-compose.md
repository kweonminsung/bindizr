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
