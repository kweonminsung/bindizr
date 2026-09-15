FROM rust:1.98-bookworm AS builder

WORKDIR /usr/src/bindizr

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release --bin bindizr --bin bindizr-external-dns

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/bindizr --create-home --shell /usr/sbin/nologin bindizr \
    && mkdir -p /etc/bindizr /run/bindizr /var/lib/bindizr \
    && chown -R bindizr:bindizr /etc/bindizr /run/bindizr /var/lib/bindizr

COPY --from=builder /usr/src/bindizr/target/release/bindizr /usr/local/bin/bindizr
# ExternalDNS webhook adapter, run as a sidecar next to external-dns.
COPY --from=builder /usr/src/bindizr/target/release/bindizr-external-dns /usr/local/bin/bindizr-external-dns
COPY --chown=bindizr:bindizr docker/bindizr.conf.toml /etc/bindizr/bindizr.conf.toml

RUN setcap cap_net_bind_service=+ep /usr/local/bin/bindizr

USER bindizr

EXPOSE 8000/tcp 53/tcp 53/udp

# The daemon's own socket answers this, so the image needs no HTTP client, and
# a database outage does not restart the container into a crash loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["bindizr", "status"]

CMD ["bindizr", "start"]
