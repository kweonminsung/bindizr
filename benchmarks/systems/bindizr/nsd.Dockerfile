# No multi-arch NSD image is published, so the benchmark builds a minimal one.
FROM alpine:3.22
RUN apk add --no-cache nsd
