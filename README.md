<div align="center">
<p align="center">
    <img src="public/bindizr_horizontal.png" width="400px">
</p>

DNS Synchronization Service for BIND9

<p>
    <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
        <img src="https://img.shields.io/badge/license-Apache 2.0-blue" />
    </a>
    <a href="https://github.com/kweonminsung/bindizr/actions/workflows/build_test.yaml">
        <img src="https://github.com/kweonminsung/bindizr/actions/workflows/build_test.yaml/badge.svg" />
    </a>
    <br>
    <a href="https://app.codacy.com/gh/kweonminsung/bindizr/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade">
        <img src="https://app.codacy.com/project/badge/Grade/29665b2525ce453bb78429b13ec8ede9" />
    </a>
</p>
</div>

## Concepts

**Bindizr** is a Rust-based daemon and HTTP API that synchronizes DNS records between bind9 and a database (MySQL, PostgreSQL, or SQLite).

- It reads and writes zone configurations from a bind config directory.

- Changes made via HTTP API are stored in the database and written to zone files.

- After updates, bindizr sends RNDC commands to bind9 to reload zone data.

<br>

&nbsp;<img src="public/concepts.png" width="462px">

## Get Started

### 1. Install BIND9

#### Debian (Ubuntu, etc.)
```bash
$ sudo apt-get update
$ sudo apt-get install sudo ufw dnsutils bind9
$ sudo ufw allow 953/tcp
```

#### Red Hat (Fedora, CentOS, etc.)
```bash
$ sudo yum install bind bind-utils
$ sudo firewall-cmd --add-port=953/tcp --permanent
$ sudo firewall-cmd --reload
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

### 3. Configure RNDC and BIND

We provide two methods for configuring BIND and RNDC: a recommended automated script and a manual setup.

#### Recommended: Automated Setup Script

This script automatically detects your BIND configuration directory, generates an RNDC key if needed, and updates your `named.conf` file.

```bash
# Download and run the setup script
$ wget -qO- https://raw.githubusercontent.com/kweonminsung/bindizr/main/scripts/setup_bind_rndc.sh | sudo bash

# Restart bind service
$ sudo systemctl restart bind9  # For Debian-based systems
$ sudo systemctl restart named  # For Red Hat-based systems
```

<details>
<summary>Alternative: Manual Setup</summary>

First, set variables for your BIND configuration. The paths vary depending on your operating system.

- **For Debian-based systems (e.g., Ubuntu):**
  ```bash
  $ BIND_CONF_DIR=/etc/bind
  $ BIND_CONF_FILE=/etc/bind/named.conf
  $ RNDC_KEY_FILE=/etc/bind/rndc.key
  ```
- **For Red Hat-based systems (e.g., Fedora, CentOS):**
  ```bash
  $ BIND_CONF_DIR=/etc/named
  $ BIND_CONF_FILE=/etc/named.conf
  $ RNDC_KEY_FILE=/etc/rndc.key
  ```

Now, generate the RNDC configuration and key using the variable:
```bash
# Generate RNDC configuration and key
$ rndc-confgen -a

# View the generated key (example below)
$ cat $RNDC_KEY_FILE

# Output:
key "rndc-key" {
    algorithm hmac-sha256;  # The algorithm used for RNDC authentication (must match on both sides)
    secret "RNDC_SECRET_KEY";  # Shared secret key (base64 encrypted)
};
```

Now, update your main BIND configuration file (`$BIND_CONF_FILE`) by adding the following lines. This ensures that BIND loads both the Bindizr configuration and the RNDC key.

```bash
# Append the include statements to named.conf
echo "
include \"$BIND_CONF_DIR/bindizr/named.conf.bindizr\";
include \"$RNDC_KEY_FILE\";
" | sudo tee -a "$BIND_CONF_FILE"
```

You also need to add a `controls` block to allow `rndc` to connect. If you don't have one, add the following:
```
controls {
    # Listens on all interfaces (0.0.0.0) using port 953 (default RNDC port)
    # Adjust IP and port as needed for your environment.
    inet 0.0.0.0 port 953
        allow { any; } keys { "rndc-key"; };

    # For example, to restrict RNDC to localhost only:
    # inet 127.0.0.1 port 953
    #     allow { 127.0.0.1; } keys { "rndc-key"; };

    # Or to allow only specific internal network:
    # inet 192.168.1.10 port 953
    #     allow { 192.168.1.0/24; } keys { "rndc-key"; };
};
```

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
host = "127.0.0.1"             # HTTP API host
port = 3000                    # HTTP API port
require_authentication = true  # Enable API authentication (true/false)

[database]
type = "mysql"                 # Database type: mysql, sqlite, postgresql

[database.mysql]
server_url = "mysql://user:password@hostname:port/database"      # Mysql server configuration

[database.sqlite]
file_path = "bindizr.db"       # SQLite database file path

[database.postgresql]
server_url = "postgresql://user:password@hostname:port/database" # PostgreSQL server configuration

[bind]
bind_config_path = "$BIND_CONF_DIR"       # Bind config path
rndc_server_url = "127.0.0.1:953"    # RNDC server address
rndc_algorithm = "sha256"            # RNDC authentication algorithm
rndc_secret_key = "RNDC_SECRET_KEY"  # RNDC secret key

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
```

### 5. Start Bindizr

```bash
# Start Bindizr service
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

# Overwrite DNS configuration file
$ bindizr dns write

# Reload DNS configuration
$ bindizr dns reload

# Show help information
$ bindizr --help
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
- [`sqlx`](https://docs.rs/sqlx/latest/sqlx/) - An async, pure Rust SQL crate featuring compile-time checked queries without a DSL.
- [`rndc`](https://crates.io/crates/rndc) – A library for interacting with BIND's Remote Name Daemon Control (RNDC) protocol.



### License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
