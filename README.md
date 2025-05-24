# Bindizr

Synchronizing bind9(DNS) records with DB

## Concepts

**Bindizr** is a Rust-based daemon and HTTP API that synchronizes DNS records between bind9 and a MySQL database.

- It reads and writes zone configurations from a bind config directory.

- Changes made via HTTP API are stored in the database and written to zone files.

- After updates, bindizr sends RNDC commands to bind9 to reload zone data.

<br>

&nbsp;<img src="public/concepts.png" width="462px" height="200x">

## Get Started

### 1. Install BIND9

```bash
$ sudo apt-get update
$ sudo apt-get install sudo ufw dnsutils bind9
$ ufw allow 953/tcp
```

### 2. Configure RNDC and BIND

```bash
# Generate RNDC configuration and key
$ rndc-confgen [-A KEY_ALGORITHM] > /etc/bind/rndc.conf

# View the generated key (example below)
$ cat /etc/bind/rndc.conf
# Output:
key "rndc-key" {
    algorithm hmac-sha256;  # The algorithm used for RNDC authentication (must match on both sides)
    secret "cqEa3Oo1CnCgKivL6hdUwuCzlfRH68yeAdrsGeF3Pu0=";  # Shared secret key
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
```

### 3. Restart Services

```bash
$ service bind restart

$ echo '
[server]
port = 3000

[mysql]
server_url = "mysql://root:kweonminsungabcd1234@3.39.183.190:50004/bindizr"

[bind]
bind_config_path = "temp"
rndc_algorithm = "hmac-sha256"
rndc_secret_key = "cqEa3Oo1CnCgKivL6hdUwuCzlfRH68yeAdrsGeF3Pu0="
rndc_server_url = "127.0.0.1:953"
' > bindizr.conf

$ ./bindizr start
```

## Dependencies

- [hyper](https://hyper.rs/)
- [mysql](https://crates.io/crates/mysql/)
- [rndc](https://crates.io/crates/rndc)
