//! Readers for what a CLI command printed: the import summary table and the
//! DNSSEC status a later assertion compares against.

use crate::common::TestApp;

/// The `zone import` summary row: PARSED ADDED DELETED UPDATED UNCHANGED SKIPPED.
pub(crate) fn summary_cells(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .skip_while(|line| !line.contains("APPLIED"))
        .nth(1)
        .expect("import printed a summary table")
        .split_whitespace()
        .collect()
}

/// The count cells of an import summary table, after its APPLIED and DRY-RUN
/// flags.
pub(crate) fn summary_row(stdout: &str) -> Vec<&str> {
    summary_cells(stdout)[2..].to_vec()
}

/// Read a test zone's DNSSEC status through the CLI.
pub(crate) async fn read_dnssec_status(app: &TestApp, zone_name: &str) -> serde_json::Value {
    let status = app
        .run_cli_success(&["dnssec", "status", zone_name, "--output", "json"])
        .await;
    serde_json::from_str(&status).expect("CLI did not return valid JSON")
}

/// Read the active signing key tag for a test zone.
pub(crate) async fn read_signing_key_tag(app: &TestApp, zone_name: &str) -> u64 {
    read_dnssec_status(app, zone_name).await["keys"][0]["key_tag"]
        .as_u64()
        .expect("status lists the signing key")
}
