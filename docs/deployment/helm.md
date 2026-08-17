# Helm

Use the Helm chart to deploy Bindizr, BIND9 secondary pods, and optional bundled
MySQL/PostgreSQL in Kubernetes.

## Production: external database

Create a Kubernetes Secret that points Bindizr to your external MySQL or
PostgreSQL database:

```bash
$ kubectl create secret generic bindizr-db-secret \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'

$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

## Development: bundled database

For development, the chart can run a single-replica MySQL or PostgreSQL
StatefulSet:

```bash
$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.type=postgresql \
  --set bindizr.database.existingSecret= \
  --set postgresql.enabled=true
```

!!! note "SQLite is not supported by the Helm chart"

    A pod-local SQLite file cannot be shared across replicas or survive
    rescheduling. Use MySQL or PostgreSQL on Kubernetes.

See the [chart documentation](https://github.com/kweonminsung/bindizr/blob/main/charts/README.md)
for all Helm values and examples, including bindizr-ui.
