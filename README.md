# Bindizr

Synchronizing bind9(DNS) records with DB

### Concepts

<img src="public/concepts.png" width="420px" height="200x">

### Dependencies

- [hyper](https://hyper.rs/)
- [mysql](https://crates.io/crates/mysql/)

```bash
Run apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    net-tools \
    dnsutils \
    bind9 \
    ufw \
    sudo

rndc-confgen > /etc/rndc.conf
rndc-confgen -A hmac-sha224
```
