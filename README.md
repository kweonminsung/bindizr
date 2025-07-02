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

**Bindizr** is a Rust-based daemon and HTTP API that synchronizes DNS records between bind9 and a MySQL database.

- It reads and writes zone configurations from a bind config directory.

- Changes made via HTTP API are stored in the database and written to zone files.

- After updates, bindizr sends RNDC commands to bind9 to reload zone data.

<br>

&nbsp;<img src="public/concepts.png" width="462px">

## Get Started

### 1. Install BIND9

```bash
$ sudo apt-get update
$ sudo apt-get install sudo ufw dnsutils bind9
$ ufw allow 953/tcp
```

### 2. Download Bindizr and Install

You can download the latest bindizr binary from [Release](https://github.com/kweonminsung/bindizr/releases/latest).

#### Debian Packages (DPKG)

For Debian-based systems (Ubuntu, Debian, etc.), you can install Bindizr using the .deb package:

```bash
# Install using dpkg
$ sudo dpkg -i bindizr_0.1.0_amd64.deb

# Verify installation
$ bindizr
```

### 3. Configure RNDC and BIND

```bash
# Generate RNDC configuration and key
$ rndc-confgen [-A KEY_ALGORITHM] > /etc/bind/rndc.key

# View the generated key (example below)
$ cat /etc/bind/rndc.key
# Output:
key "rndc-key" {
    algorithm hmac-sha256;  # The algorithm used for RNDC authentication (must match on both sides)
    secret "RNDC_SECRET_KEY";  # Shared secret key (base64 encrypted)
};
```

Now create or update the main BIND configuration file:

```bash
# Compose the main named.conf
$ echo '
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

include "/etc/bind/bindizr/named.conf.bindizr";
include "/etc/bind/rndc.key";

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

' > /etc/bind/named.conf

# Restart bind service
$ service bind restart
```

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
bind_config_path = "/etc/bind"       # Bind config path
rndc_server_url = "127.0.0.1:953"    # RNDC server address
rndc_algorithm = "sha256"            # RNDC authentication algorithm
rndc_secret_key = "RNDC_SECRET_KEY"  # RNDC secret key

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
enable_file_logging = true    # Enable logging to file (true/false)
log_file_path = "/var/log/bindizr"         # Path to log file (absolute or relative)
```

### 5. Start Bindizr

```bash
# Start Bindizr service
$ bindizr start

# Runs bindizr in foreground mode
$ bindizr start -f

# Create an API token for authentication
$ bindizr token create
```

## Usage and Options

Bindizr provides a command-line interface for managing the DNS synchronization service and API tokens.

### Basic Commands

```bash
# Start the bindizr service in background mode
$ bindizr start

# Start the bindizr service in foreground mode
$ bindizr start -f

# Start with a custom configuration file
$ bindizr start -c <FILE>

# Stop the bindizr service
$ bindizr stop

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
- [`mysql`](https://crates.io/crates/mysql) – A MySQL database driver for Rust.
- [`rndc`](https://crates.io/crates/rndc) – A library for interacting with BIND's Remote Name Daemon Control (RNDC) protocol.



### License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).