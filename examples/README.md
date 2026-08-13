# Examples

Self-contained environments for running the full bindizr stack (bindizr,
BIND9 secondaries, PostgreSQL). All commands run from the repository root.

| Directory | Stack | Use it for |
| --- | --- | --- |
| [`compose/`](compose/) | Docker Compose: bindizr, 2× BIND9, dnsdist load balancer, PostgreSQL | Local development and testing |
| [`swarm/`](swarm/) | Docker Swarm: bindizr, global BIND9 service, PostgreSQL | A containerized deployment template |
| [`kind/`](kind/) | 3-node Kubernetes cluster running the Helm chart, with an optional ExternalDNS setup | Testing the chart and the ExternalDNS integration without a cloud cluster |

## compose

Builds bindizr from the working tree (`bindizr:local`) and wires two BIND9
secondaries behind a dnsdist load balancer:

```sh
docker compose -f examples/compose/docker-compose.yml up -d --build
```

On arm64 hosts add the override that swaps the amd64-only ISC BIND9 image
(switching between the two images requires `down -v`):

```sh
docker compose -f examples/compose/docker-compose.yml \
  -f examples/compose/docker-compose.arm.yml up -d --build
```

Host ports: API `8000`, DNS through dnsdist `127.0.0.1:53`, bindizr's own DNS
`5300`, the individual BIND9 replicas `1053`/`1054`.

## swarm

```sh
docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

Runs the published image with BIND9 as a global service (one replica per
node, host-mode port 53). See
[docs/deployment/docker-compose.md](../docs/deployment/docker-compose.md).

## kind

Requires Docker, [kind](https://kind.sigs.k8s.io/), and Helm. The cluster
config maps host `127.0.0.1:5300` (TCP/UDP) to the bind9 NodePort so `dig`
works from the host.

```sh
kind create cluster --config examples/kind/cluster.yaml
helm install bindizr charts -n bindizr --create-namespace -f examples/kind/values.yaml
```

On arm64 hosts the Docker Hub bindizr image is unusable (amd64-only): build
it locally, load it into the cluster, and add the arm values overlay:

```sh
docker build -t bindizr:local .
kind load docker-image bindizr:local --name bindizr-test
helm install bindizr charts -n bindizr --create-namespace \
  -f examples/kind/values.yaml -f examples/kind/values.arm.yaml
```

Once the pods are Running, pin the bind9 NodePort to the mapped port (the
chart does not expose `nodePort` in values) and query from the host:

```sh
kubectl -n bindizr patch svc bindizr-bind9 --type merge -p '{"spec":{"ports":[{"name":"dns-tcp","port":53,"targetPort":"dns-tcp","protocol":"TCP","nodePort":30053},{"name":"dns-udp","port":53,"targetPort":"dns-udp","protocol":"UDP","nodePort":30053}]}}'
dig -p 5300 @127.0.0.1 <zone> SOA
```

The HTTP API is reachable through a port-forward
(`kubectl -n bindizr port-forward svc/bindizr-api 8000:8000` →
`http://127.0.0.1:8000`).
Tear everything down with `kind delete cluster --name bindizr-test`.

### ExternalDNS

Runs [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) against
bindizr's webhook provider API — hostname annotations on Services become
records in a bindizr-managed zone. Full reference:
[docs/external-dns.md](../docs/external-dns.md).

```sh
# 1. Enable the provider API (config file change, so restart bindizr).
helm upgrade bindizr charts -n bindizr -f examples/kind/values.yaml \
  -f examples/kind/values.external-dns.yaml   # plus values.arm.yaml on arm64
kubectl -n bindizr rollout restart deploy/bindizr

# 2. Create the zone ExternalDNS will manage, and a token granted to it.
kubectl -n bindizr exec deploy/bindizr -- bindizr zone create --name example.com \
  --primary-ns ns.example.com --admin-email admin@example.com --ttl 3600
kubectl -n bindizr exec deploy/bindizr -- bindizr token create --name external-dns
kubectl -n bindizr exec deploy/bindizr -- bindizr zone token-policy add example.com --token external-dns
kubectl -n bindizr create secret generic bindizr-external-dns --from-literal=api-token=<token>

# 3. Deploy ExternalDNS + adapter sidecar and the annotated demo Service.
kubectl -n bindizr apply -f examples/kind/external-dns.yaml

# 4. Within a sync interval the record exists and BIND9 serves it.
dig -p 5300 @127.0.0.1 app.example.com A
```

On arm64, edit the adapter image in `external-dns.yaml` to the locally built
`bindizr:local` (with `imagePullPolicy: Never`) first.
