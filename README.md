<div align="center">
<p align="center">
    <img src="public/bindizr_horizontal.png" width="400px">
</p>

DNS Synchronization Service for BIND9

<p>
    <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
        <img src="https://img.shields.io/badge/license-Apache 2.0-blue" />
    </a>
    <a href="https://github.com/kweonminsung/bindizr/actions/workflows/ci.yml">
        <img src="https://github.com/kweonminsung/bindizr/actions/workflows/ci.yml/badge.svg" />
    </a>
    <br>
    <a href="https://app.codacy.com/gh/kweonminsung/bindizr/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade">
        <img src="https://app.codacy.com/project/badge/Grade/29665b2525ce453bb78429b13ec8ede9" />
    </a>
</p>
</div>

**Bindizr** is a Rust-based DNS control plane that manages zones and records via an HTTP API or CLI, stores data in a database backend (MySQL, PostgreSQL, or SQLite), and propagates changes to BIND9 secondary servers via AXFR/IXFR using DNS Catalog Zones.

## Concepts

- **Control Plane**: Manage DNS zones and records through HTTP API or CLI commands. All changes are stored in the database (MySQL, PostgreSQL, or SQLite).

- **XFR Server**: Built-in AXFR (full zone transfer) and IXFR (incremental zone transfer) server that serves zone data to secondary DNS servers. SOA serial numbers are automatically incremented on each change.

- **Catalog Zones**: Bindizr uses DNS Catalog Zones (RFC 9432) to automatically propagate zone configuration to BIND9 secondary servers. When you create or delete a zone via the API/CLI, BIND9 automatically discovers and configures it without manual intervention.

- **Secondary DNS Servers**: Standard BIND9 (or any RFC-compliant DNS server) instances configured as secondaries. They automatically discover zones through the catalog zone, pull zone updates from Bindizr's XFR server via zone transfer, and respond to DNS queries from clients.

- **nsupdate (Dynamic Update)**: Supports RFC 2136-style DNS dynamic updates via nsupdate.

<br>

&nbsp;<img src="public/concepts.png" width="462px">

## Deployment Options

Bindizr can be deployed with Helm, Docker Compose for Docker Swarm, or a manual package-based setup.

### Helm

Use the Helm chart to deploy Bindizr, BIND9 secondary pods, and optional bundled MySQL/PostgreSQL in Kubernetes.

For production, create a Kubernetes Secret that points Bindizr to your external MySQL or PostgreSQL database:

```bash
$ helm repo add bindizr https://kweonminsung.github.io/bindizr/charts
$ helm repo update

$ kubectl create secret generic bindizr-db-secret \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'

$ helm install bindizr bindizr/bindizr-stack \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

For development, the chart can run a single-replica MySQL or PostgreSQL StatefulSet:

```bash
$ helm install bindizr bindizr/bindizr-stack \
  --set bindizr.database.type=postgresql \
  --set bindizr.database.existingSecret= \
  --set postgresql.enabled=true
```

SQLite is not supported by the Helm chart. See [charts/bindizr-stack](charts/bindizr-stack/README.md) for all Helm values and examples, including TSIG and bindizr-ui.

### Docker Compose

Use the default `docker-compose.yml` with Docker Swarm for a containerized Bindizr deployment.

```bash
$ docker stack deploy -c docker-compose.yml bindizr
```

The stack runs Bindizr, PostgreSQL, and BIND9 on an overlay network, using Docker configs for BIND9 configuration.

### Manual Installation

For package-based installation on a VM or bare-metal host, follow the manual installation guide below. It installs BIND9, installs the Bindizr binary or package, configures BIND9 as a secondary using the catalog zone, and starts Bindizr as a system service.

## Bindizr Configuration

Bindizr can read configuration from `/etc/bindizr/bindizr.conf.toml` and can also be configured with environment variables in container deployments. The Docker files in this repository set the same options through environment variables.

For manual installation, create the configuration file:

```bash
$ vim /etc/bindizr/bindizr.conf.toml # or use any text editor you prefer
```

Add the following configuration, adjusting values to match your environment:

```toml
[api]
listen_addr = "127.0.0.1"     # HTTP API listen address
listen_port = 3000            # HTTP API listen port
require_authentication = true # Enable API authentication (true/false)

[database]
type = "mysql"                # Database type: mysql, sqlite, postgresql

[database.mysql]
server_url = "mysql://user:password@hostname:port/database" # Mysql server configuration

[database.sqlite]
file_path = "bindizr.db"      # SQLite database file path

[database.postgresql]
server_url = "postgresql://user:password@hostname:port/database" # PostgreSQL server configuration

[dns]
listen_addr = "127.0.0.1"     # DNS server listen address
listen_port = 53              # DNS server listen port (UDP and TCP)
secondary_addrs = ""          # Comma-separated secondary DNS server addresses for NOTIFY (e.g., "192.168.1.2:53,192.168.1.3:53")
notify_after_update = true    # Send DNS NOTIFY after zone changes
notify_on_startup = false     # Send DNS NOTIFY when bindizr starts
notify_retries = 3            # Retry count after the initial NOTIFY attempt
notify_timeout_secs = 5       # Timeout in seconds for each NOTIFY send/response wait
nsupdate_allow_unsigned = false # Accept unsigned nsupdate requests (not recommended in production; TSIG keys/policies are managed via CLI or HTTP API)

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
```

## Manual Installation

### 1. Install BIND9

#### Debian (Ubuntu, etc.)
```bash
$ sudo apt-get update
$ sudo apt-get install sudo ufw dnsutils bind9
```

#### Red Hat (Fedora, CentOS, etc.)
```bash
$ sudo yum install bind bind-utils
```

### 2. Download Bindizr and Install

You can download the latest bindizr binary from [Release](https://github.com/kweonminsung/bindizr/releases/latest).

For building from source, see the [packaging documentation](packaging/README.md).

#### Debian Packages (DPKG)

For Debian-based systems (Ubuntu, Debian, etc.), you can install Bindizr using the .deb package:

```bash
# Install using dpkg
$ sudo dpkg -i bindizr_0.1.0_amd64.deb

# Verify installation
$ bindizr
```
#### Red Hat Packages (RPM)

For Red Hat-based systems (Fedora, CentOS, RHEL, etc.), you can install Bindizr using the .rpm file:

```bash
# Install the .rpm package
$ sudo rpm -i bindizr_0.1.0_amd64.rpm

# Verify installation
$ bindizr
```

### 3. Configure BIND as Secondary with Catalog Zone

We provide two methods for configuring BIND: a recommended automated script and a manual setup.

#### Recommended: Automated Setup Script

This script automatically detects your BIND configuration directory and configures BIND to use Bindizr's catalog zone for automatic zone discovery.

```bash
# Download and run the setup script
$ wget -qO- https://raw.githubusercontent.com/kweonminsung/bindizr/main/packaging/scripts/setup_bind.sh | sudo bash

# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

<details>
<summary>Alternative: Manual Setup</summary>

First, set variables for your BIND configuration. The paths vary depending on your operating system.

- **For Debian-based systems (e.g., Ubuntu):**
  ```bash
  $ BIND_CONF_FILE=/etc/bind/named.conf
  $ BIND_CACHE_DIR=/var/cache/bind
  ```
- **For Red Hat-based systems (e.g., Fedora, CentOS):**
  ```bash
  $ BIND_CONF_FILE=/etc/named.conf
  $ BIND_CACHE_DIR=/var/named/slaves
  ```

Update your main BIND configuration file (`$BIND_CONF_FILE`) by adding the following:

```bash
# Configure catalog zone support
cat <<EOF | sudo tee -a "$BIND_CONF_FILE"
options {
    allow-notify { any; };
    ixfr-from-differences yes;
    catalog-zones {
        zone "catalog.bind" default-primaries { 127.0.0.1 port 53; };
    };
};
EOF

# Add catalog zone as secondary
cat <<EOF | sudo tee -a "$BIND_CONF_FILE"
zone "catalog.bind" {
    type secondary;
    primaries { 127.0.0.1 port 53; };
    file "$BIND_CACHE_DIR/catalog.bind.zone";
    allow-notify { any; };
    ixfr-from-differences yes;
};
EOF
```

**Note**: The `catalog.bind` zone automatically manages all zones created in Bindizr. When you create a new zone via the API or CLI, BIND will automatically configure it as a secondary zone without requiring manual configuration.

After saving the changes, restart the BIND service:
```bash
# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

</details>

### 4. Configure Bindizr Options

Create `/etc/bindizr/bindizr.conf.toml` using the [Bindizr Configuration](#bindizr-configuration) section above, adjusting values to match your environment.

### 5. Start Bindizr Service

```bash
# Start Bindizr service
$ sudo systemctl enable bindizr
$ sudo systemctl start bindizr

# Create an API token for authentication
$ bindizr token create
```

## Usage and Options

Bindizr provides a command-line interface for managing the DNS synchronization service and API tokens.

### Basic Commands

```bash
# Start bindizr on foreground
$ bindizr start

# Start with a custom configuration file
$ bindizr start -c <FILE>

# Check the current status of bindizr service
$ bindizr status

# Validate a configuration file without starting bindizr (defaults to /etc/bindizr/bindizr.conf.toml)
$ bindizr config check [<FILE>]

# Show the configuration loaded by the running daemon
$ bindizr config list

# Show a single configuration value by dotted key
$ bindizr config get dns.secondary_addrs

# Send NOTIFY to secondary DNS servers for a zone
$ bindizr zone notify <ZONE_NAME>

# Update a zone, changing only the fields you pass
$ bindizr zone update <ZONE_NAME> --refresh 300 --retry 60

# Update a record, changing only the fields you pass
$ bindizr record update <RECORD_ID> --value 127.0.0.1

# Export a zone as BIND master-file text (the inverse of import)
$ bindizr zone export <ZONE_NAME>

# Preview a bulk insert or zone-file import as a +/-/~ diff (applies nothing)
$ bindizr record bulk records.json --zone <ZONE_NAME> --preview
$ bindizr zone import <ZONE_NAME> zone.txt --preview

# List a zone's snapshots (SOA serials are a plain counter starting at 1)
$ bindizr zone snapshot list <ZONE_NAME>

# Diff the records between two serials (omit the second to compare to current)
$ bindizr zone snapshot diff <ZONE_NAME> <FROM_SERIAL> [<TO_SERIAL>]

# Inspect the zone state captured at a serial
$ bindizr zone snapshot get <ZONE_NAME> <SERIAL>

# Roll a zone back to a previous serial (the serial still advances)
$ bindizr zone snapshot rollback <ZONE_NAME> <SERIAL> [--dry-run]

# Check how far each secondary has caught up with a zone
$ bindizr zone status <ZONE_NAME>

# Show help information
$ bindizr --help
```

### nsupdate (Dynamic Update)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. Authorization is built from two pieces:

- **Keys** are standalone, reusable resources (name, HMAC algorithm, base64
  secret). The key name is what appears on the wire in a signed request.
  A key created with `--global` may update every zone — including zones
  created later — without any policy; this is fixed at creation.
- **Policies** grant a non-global key update rights in one zone, optionally
  restricted to a record name pattern and record types.

For each incoming update, bindizr resolves the key named in the TSIG record
and verifies the signature and signing time. A global key is then authorized
for everything; for any other key, bindizr loads its policies for the target
zone and every record in the update must match at least one of them (name
pattern and type). Otherwise the whole update is refused and nothing is
partially applied.

```bash
# Create a key (the secret is generated and printed once; use `get` to re-read it)
$ bindizr tsig-key create --name update-key

# Or import an existing base64 secret / pick another HMAC algorithm
$ bindizr tsig-key create --name legacy-key --algorithm hmac-sha512 --secret "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="

# Or create a global key that may update every zone, including future ones,
# without any policy. This is write access to all DNS data — use sparingly.
$ bindizr tsig-key create --name admin-key --global

# Grant a (non-global) key update rights in a zone (pattern/types default to '*')
$ bindizr zone tsig-policy add example.com --key update-key
$ bindizr zone tsig-policy add example.com --key acme-key --pattern "*" --types "TXT"

# Send a signed update (hmac-sha256 by default)
$ nsupdate -y "hmac-sha256:update-key:<BASE64_SECRET>" <<EOF
server 127.0.0.1 53
zone example.com
update add sub.example.com. 300 A 1.2.3.4
send
EOF
```

A zone with no policies refuses nsupdate, except from global keys, which may
update any zone. Setting `dns.nsupdate_allow_unsigned = true` accepts unsigned
requests for every zone, regardless of its policies; this is not recommended
in production (signed requests are always verified).

### TSIG Key Management

```bash
# List all TSIG keys (secrets are not shown)
$ bindizr tsig-key list

# Show one key including its secret
$ bindizr tsig-key get update-key

# Delete a key (refused while zone TSIG policies still reference it)
$ bindizr tsig-key delete update-key

# Inspect or revoke a zone's policies
$ bindizr zone tsig-policy list example.com
$ bindizr zone tsig-policy remove example.com <POLICY_ID>
```

TSIG keys and policies are also manageable over the HTTP API
(`/tsig-keys`, `/zones/{name}/tsig-policies`).

### Token Management

Bindizr uses API tokens for authentication. You can manage these tokens using the following commands:

```bash
# Create a new API token
$ bindizr token create --description "API access for monitoring"

# Create a token with expiration
$ bindizr token create --description "Temporary access" --expires-in-days 30

# List all API tokens
$ bindizr token list

# Delete an API token by ID
$ bindizr token delete <TOKEN_ID>

# Show token command help
$ bindizr token --help
```

## API Documentation

The full HTTP API documentation is available at:  
👉 [https://kweonminsung.github.io/bindizr/api/](https://kweonminsung.github.io/bindizr/api/)


### API Authentication

When making API requests, include the token in the Authorization header:

```bash
$ curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/zones
```

## Benchmarks

Bindizr measured against PowerDNS Authoritative, Technitium DNS, Knot DNS, CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and container limits — the suite lives in [benchmarks/](benchmarks/README.md). Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each container capped at 4 CPU / 4 GB.

### No overhead on the query path

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/benchmarks/b08_query_throughput_dark.svg">
  <img alt="DNS query throughput: CoreDNS 62,696 QPS, Bindizr + BIND9 62,448, Native BIND9 61,629, PowerDNS 60,406, Knot DNS 41,289, Technitium 13,139" src="public/benchmarks/b08_query_throughput_light.svg" width="900">
</picture>

Bindizr never answers a client query — the BIND9 secondaries do. `Bindizr + BIND9` serves **62,448 QPS against native BIND9's 61,629** (−1.3%, within run-to-run noise), and Bindizr itself draws 0.7% CPU under that load.

### Bulk import

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/benchmarks/b02_bulk_import_dark.svg">
  <img alt="Bulk import of 10,000 records: Bindizr zone file 132,720 records/sec, BIND9 + rndc 102,641, Bindizr bulk API 93,364, PowerDNS 36,443, Knot DNS 18,514, CoreDNS 10,374, Technitium 9,244" src="public/benchmarks/b02_bulk_import_light.svg" width="900">
</picture>

A 10,000-record zone file imports in **76 ms**; the same records through the bulk record API take 107 ms. Both paths commit to the database, so the zone survives a restart and transfers to the secondaries immediately.

### Incremental transfers stay incremental

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/benchmarks/b05_ixfr_size_dark.svg">
  <img alt="IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count" src="public/benchmarks/b05_ixfr_size_light.svg" width="900">
</picture>

A snapshot per SOA serial means an IXFR carries only what changed: **736 B for a single change in a 100,000-record zone**, where the full zone is 5.5 MB. PowerDNS answers the same request with the entire zone; Knot DNS and Technitium track the Bindizr curve.

### Write path

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/benchmarks/b03_propagation_dark.svg">
  <img alt="Median record-create latency from API call to DNS visibility: Technitium 0.6 to 4.6 ms, PowerDNS 2.8 to 7.3 ms, Knot DNS 16.2 to 20.4 ms, BIND9 + nsupdate 17.2 to 21.5 ms, Bindizr + BIND9 6.4 to 65.7 ms" src="public/benchmarks/b03_propagation_light.svg" width="900">
</picture>

A create is acknowledged in **6.4 ms** and answers from the secondaries **65.7 ms** after the call (p95 83 ms, no timeouts). Bindizr commits to the database and propagates by NOTIFY + IXFR, where the integrated servers answer from their own process as soon as they accept the write.

### Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 198.1 | 197.1 | 186.8 | **13,916.9** | **2.82 ms** | 0.00% |
| Technitium DNS | **8,992.2** | **8,182.1** | **9,123.3** | 10,594.2 | 3.51 ms | 0.00% |
| Knot DNS | 759.2 | 1,116.3 | 735.1 | 1,203.1 | 36.73 ms | 0.00% |
| BIND9 + nsupdate | 412.8 | 948.2 | 411.4 | 1,199.7 | 36.92 ms | 0.00% |
| PowerDNS Authoritative | 87.4 | 72.1 | 83.9 | 2,962.0 | 4.27 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the per-record write rate — servers that hold the zone in memory do more per second here. These runs use SQLite; PostgreSQL raises creates from 199 to 571/sec. Read is a management-plane read: an API `GET` where there is an API, a `dig` subprocess otherwise, so those p95s carry process-spawn cost.

### Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory |
| --- | --- | --- | --- | --- | --- |
| SQLite | 198.6 | 14,236.1 | 2.78 ms | 0.96 s (104,391/sec) | 120 MB |
| MySQL | 262.0 | 12,766.3 | 4.35 ms | 2.04 s (48,994/sec) | 879 MB |
| PostgreSQL | 571.3 | 12,432.4 | 4.23 ms | 1.98 s (50,647/sec) | 325 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.

<details>
<summary>Software under test</summary>

| Software | Version |
| --- | --- |
| BIND9 | `internetsystemsconsortium/bind9:9.21` |
| Bindizr | built from source |
| CoreDNS | `coredns/coredns:1.14.6` |
| Knot DNS | `cznic/knot:3.5` |
| MySQL | `mysql:9.7` |
| PostgreSQL | `postgres:18` |
| PowerDNS | `powerdns/pdns-auth-49` |
| Technitium | `technitium/dns-server` |

</details>

## Roadmap

The following features are planned for future releases. The roadmap may change based on implementation complexity and community feedback.

* [ ] **`bindizr doctor`**

  * Diagnose configuration, database connectivity, file permissions, BIND9 connectivity, and DNS synchronization issues.
  * Provide actionable warnings and recommended fixes.

* [ ] **Prometheus metrics**

  * Expose operational metrics through a `/metrics` endpoint.
  * Include API request latency, database operation duration, zone synchronization status, reload results, NOTIFY results, and error counts.
  * Provide example Prometheus scrape configuration and Grafana dashboards.

* [ ] **DNSSEC support**

  * Support DNSSEC signing and key lifecycle management.
  * Provide configurable KSK/ZSK generation, rotation, and rollover policies.
  * Expose DS records and signing status through the API and CLI.
  * Support integration with externally managed keys and BIND9 DNSSEC tooling.

## Contributing

Bug reports, documentation fixes, and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the test and lint commands, and the project conventions a review will check against.

### License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
