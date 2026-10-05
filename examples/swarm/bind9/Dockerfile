FROM debian:13-slim

# The Swarm startup command needs a shell, getent, and sed to render the VIP.
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9 bind9-utils \
    && install -d -o bind -g bind /run/named \
    && rm -rf /var/lib/apt/lists/*

VOLUME /var/lib/bind
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/usr/sbin/named", "-g"]
