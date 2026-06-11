#[test]
#[ignore = "requires docker compose and bind9"]
fn dns_bind_e2e_requires_external_stack() {
    // This is a placeholder for a full DNS/BIND E2E stack:
    // 1. Start bindizr, its database, and a BIND9 secondary with Docker Compose.
    // 2. Create a zone and records through the public HTTP API.
    // 3. Verify AXFR/IXFR/NOTIFY behavior and query answers with dig or a DNS client.
    //
    // The repository does not currently include that Compose environment, so the
    // default test suite keeps this out of band.
}
