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

## Get Started

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

Create a configuration file for Bindizr:

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
nsupdate_tsig_key = ""            # Shared TSIG secret for nsupdate authentication (empty to disable, base64 recommended)

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
```

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

# Send NOTIFY to secondary DNS servers for a zone
$ bindizr notify zone <ZONE_NAME>

# Show help information
$ bindizr --help
```

### nsupdate (Dynamic Update)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener.

```bash
$ nsupdate <<EOF
server 127.0.0.1 53
zone example.com
update add sub.example.com. 300 A 1.2.3.4
send
EOF
```

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
👉 [https://kweonminsung.github.io/bindizr/](https://kweonminsung.github.io/bindizr/)


### API Authentication

When making API requests, include the token in the Authorization header:

```bash
$ curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/zones
```

## Dependencies

This project relies on the following core dependencies:

- [`axum`](https://docs.rs/axum/latest/axum/) – A web application framework for building fast and modular APIs in Rust.
- [`utoipa`](https://docs.rs/utoipa/latest/utoipa/) - Compile-time OpenAPI generation for Rust APIs.
- [`sqlx`](https://docs.rs/sqlx/latest/sqlx/) - An async, pure Rust SQL crate featuring compile-time checked queries without a DSL.



### License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
