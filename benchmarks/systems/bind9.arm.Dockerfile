# Multi-arch BIND9 for ARM hosts: the ISC image is amd64-only and segfaults
# under emulation, and the ubuntu/bind9 rock ships no shell for the templating
# entrypoints. Debian's bind9 is 9.20 against ISC's 9.21.
FROM debian:13
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9 \
    && rm -rf /var/lib/apt/lists/*
