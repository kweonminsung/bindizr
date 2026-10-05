# Examples

Self-contained environments for running the full Bindizr stack (Bindizr,
BIND secondaries, PostgreSQL). All commands run from the repository root.

| Directory | Stack | Use it for |
| --- | --- | --- |
| [`compose/`](compose/) | Docker Compose: Bindizr, 2× BIND, dnsdist load balancer, PostgreSQL | Local development and testing |
| [`swarm/`](swarm/) | Docker Swarm: Bindizr, global BIND service, PostgreSQL | A containerized deployment template |
| [`kind/`](kind/) | 3-node Kubernetes cluster running the Helm chart, with an optional ExternalDNS setup | Testing the chart and the ExternalDNS integration without a cloud cluster |

## compose

Builds Bindizr from the working tree (`bindizr:local`) and wires two BIND
secondaries behind a dnsdist load balancer:

```sh
docker compose -f examples/compose/docker-compose.yml up -d --build
```

On arm64 hosts add the override that swaps the amd64-only ISC BIND image
(switching between the two images requires `down -v`):

```sh
docker compose -f examples/compose/docker-compose.yml \
  -f examples/compose/docker-compose.arm.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, Bindizr's own DNS
`5300`, the individual BIND replicas `1053`/`1054`.

## swarm

```sh
docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

Runs the published image with BIND as a global service (one replica per
node, host-mode port 53). See
[docs/deployment/docker-compose.md](../docs/deployment/docker-compose.md).

## kind

Requires Docker, [kind](https://kind.sigs.k8s.io/), and Helm. The cluster
config maps host `127.0.0.1:5300` (TCP/UDP) to the bind9 NodePort so `dig`
works from the host.

```sh
kind create cluster --config examples/kind/cluster.yaml
```

Choose one of the install commands below. On amd64 with the published image:

```sh
helm install bindizr charts -n bindizr --create-namespace -f examples/kind/values.yaml
```

On arm64 with the published image, add the BIND image overlay:

```sh
helm install bindizr charts -n bindizr --create-namespace \
  -f examples/kind/values.yaml -f examples/kind/values.arm.yaml
```

Before the Bindizr image is published, or when testing your working tree,
build and load it locally. This command selects that image and the arm64 BIND
overlay; omit `-f examples/kind/values.arm.yaml` on amd64:

```sh
docker build -t bindizr:local .
kind load docker-image bindizr:local --name bindizr-test
helm install bindizr charts -n bindizr --create-namespace \
  -f examples/kind/values.yaml -f examples/kind/values.arm.yaml \
  --set bindizr.image.repository=bindizr \
  --set bindizr.image.tag=local --set bindizr.image.pullPolicy=Never
```

Once the pods are Running, query from the host; `values.yaml` pins the bind9
NodePort to the port the cluster config maps:

```sh
dig -p 5300 @127.0.0.1 <zone> SOA
```

The HTTP API is reachable through a port-forward
(`kubectl -n bindizr port-forward svc/bindizr-api 8000:8000` →
`http://127.0.0.1:8000`).
Tear everything down with `kind delete cluster --name bindizr-test`.

### ExternalDNS

Runs [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) against
Bindizr's webhook provider API — hostname annotations on Services become
records in a Bindizr-managed zone. Full reference:
[docs/external-dns.md](../docs/external-dns.md).

```sh
# 1. Enable the provider API; retain the install's image and database values.
#    The changed configuration rolls the bindizr pods.
helm upgrade bindizr charts -n bindizr --reuse-values \
  -f examples/kind/values.external-dns.yaml

# 2. Create the zone ExternalDNS will manage (it starts with an apex NS naming
#    the MNAME, which BIND9 needs), a role granted the record actions there,
#    and a token in that role.
kubectl -n bindizr exec deploy/bindizr -- bindizr zone create example.com \
  --mname ns.example.com --rname admin@example.com --default-ttl 3600
kubectl -n bindizr exec deploy/bindizr -- bindizr role create external-dns
kubectl -n bindizr exec deploy/bindizr -- bindizr role grant external-dns \
  --zone example.com --actions record:read,record:create,record:delete
kubectl -n bindizr exec deploy/bindizr -- bindizr token create external-dns \
  --role external-dns
export BINDIZR_TOKEN='paste-the-secret-printed-above'
kubectl -n bindizr create secret generic bindizr-external-dns \
  --from-literal=api-token="$BINDIZR_TOKEN"

# 3. Deploy ExternalDNS + adapter sidecar and the annotated demo Service.
kubectl -n bindizr apply -f examples/kind/external-dns.yaml

# 4. Within a sync interval the record exists and BIND9 serves it.
dig -p 5300 @127.0.0.1 app.example.com A
```

When testing a locally built Bindizr image, edit the adapter image in
`external-dns.yaml` to `bindizr:local` (with `imagePullPolicy: Never`) first.
