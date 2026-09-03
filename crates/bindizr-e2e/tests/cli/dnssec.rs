use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_lifecycle_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(&["zone", "dnssec", "enable", &zone_name])
        .await;
    assert!(enabled.contains("DNSSEC enabled successfully"));
    assert!(enabled.contains("DNSSEC enabled"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("DNSSEC enabled"));
    // The keys table row is `ID ROLE STATE ELIGIBLE-AT ALGORITHM KEY_TAG
    // DNSKEY`; an active key's ELIGIBLE-AT renders as `-`. The policy line
    // above the table names the algorithm too, so it is skipped.
    let key_row = status
        .lines()
        .find(|line| line.contains("ecdsap256sha256") && !line.starts_with("Policy:"))
        .expect("status lists the signing key");
    let key_tag = key_row
        .split_whitespace()
        .nth(5)
        .expect("key row carries a key tag");
    assert!(key_tag.parse::<u32>().expect("key tag is numeric") > 0);

    let ds = app
        .run_cli_success(&["zone", "dnssec", "ds", &zone_name])
        .await;
    assert!(ds.contains(&format!("IN DS {key_tag} ")), "{ds}");

    // Same algorithm, denial, and key layout as `default`: the move only
    // changes the timing, so no rollover starts.
    let policy_name = format!("{}-long", app.namespace());
    app.run_cli_success(&[
        "dnssec-policy",
        "create",
        "--name",
        &policy_name,
        "--signature-validity-days",
        "30",
        "--zsk-lifetime-days",
        "90",
    ])
    .await;
    let moved = app
        .run_cli_success(&["zone", "dnssec", "set-policy", &zone_name, &policy_name])
        .await;
    assert!(moved.contains("DNSSEC policy changed successfully"));
    assert!(
        moved.contains(&format!("Policy: {policy_name} ("))
            && moved.contains("validity 30d")
            && moved.contains("zsk-lifetime 90d"),
        "{moved}"
    );
    assert!(!moved.contains("published"), "{moved}");

    let signed_export = app
        .run_cli_success(&["zone", "export", &zone_name, "--signed"])
        .await;
    assert!(
        signed_export.contains("\tIN\tDNSKEY\t257 3 "),
        "{signed_export}"
    );
    assert!(
        signed_export.contains("\tIN\tRRSIG\tSOA "),
        "{signed_export}"
    );

    let signed = app
        .run_cli_success(&["zone", "dnssec", "sign", &zone_name])
        .await;
    assert!(signed.contains("Zone signed successfully"));

    let disabled = app
        .run_cli_success(&["zone", "dnssec", "disable", &zone_name])
        .await;
    assert!(disabled.contains("DNSSEC disabled successfully"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("DNSSEC disabled"));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_nsec3_rollover_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-roll-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let policy_name = format!("{}-nsec3", app.namespace());
    app.run_cli_success(&[
        "dnssec-policy",
        "create",
        "--name",
        &policy_name,
        "--denial",
        "nsec3",
    ])
    .await;
    let enabled = app
        .run_cli_success(&[
            "zone",
            "dnssec",
            "enable",
            &zone_name,
            "--policy",
            &policy_name,
        ])
        .await;
    assert!(enabled.contains("DNSSEC enabled successfully"));
    assert!(enabled.contains("NSEC3 denial"));

    let started = app
        .run_cli_success(&["zone", "dnssec", "rollover", "start", &zone_name])
        .await;
    assert!(started.contains("Key rollover started successfully"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("NSEC3 denial"));
    assert!(status.contains("published"), "{status}");
    assert!(status.contains("active"), "{status}");

    // The API test covers the far side of the hold-down wait.
    let ds_seen = app
        .run_cli(&["zone", "dnssec", "rollover", "ds-seen", &zone_name])
        .await;
    assert!(!ds_seen.status.success());
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_key_export_import_round_trip_via_cli() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-keys.example");
    app.create_zone_cli(&zone_name, "3600").await;
    app.run_cli_success(&["zone", "dnssec", "enable", &zone_name])
        .await;

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    let key_tag = status
        .lines()
        .find(|line| line.contains("ecdsap256sha256") && !line.starts_with("Policy:"))
        .and_then(|line| line.split_whitespace().nth(5))
        .expect("status lists the signing key")
        .to_string();

    let exported = app
        .run_cli_success(&["zone", "dnssec", "keys", "export", &zone_name])
        .await;
    let base = format!("K{zone_name}.+013+{:05}", key_tag.parse::<u32>().unwrap());
    assert!(
        exported.contains(&format!("; {base}.private")),
        "{exported}"
    );
    let dnskey_line = exported
        .lines()
        .find(|line| line.contains(" IN DNSKEY "))
        .expect("export prints the DNSKEY record");
    let private_block: String = exported
        .lines()
        .skip_while(|line| *line != format!("; {base}.private"))
        .skip(1)
        .take_while(|line| !line.starts_with("; "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        private_block.starts_with("Private-key-format:"),
        "{exported}"
    );

    let dir = tempfile::tempdir().expect("create key dir");
    let key_file = dir.path().join(format!("{base}.key"));
    let private_file = dir.path().join(format!("{base}.private"));
    std::fs::write(&key_file, format!("{dnskey_line}\n")).expect("write .key");
    std::fs::write(&private_file, private_block).expect("write .private");
    let key_file = key_file.to_str().expect("utf-8 temp dir").to_string();
    let private_file = private_file.to_str().expect("utf-8 temp dir").to_string();

    // Disable drops the keys; the import must restore the same key.
    app.run_cli_success(&["zone", "dnssec", "disable", &zone_name])
        .await;

    // Under a split-key policy the lone SEP key is a KSK with no ZSK, so the
    // import is refused before anything is stored.
    let split_policy = format!("{}-split", app.namespace());
    app.run_cli_success(&[
        "dnssec-policy",
        "create",
        "--name",
        &split_policy,
        "--split-keys",
    ])
    .await;
    let refused = app
        .run_cli(&[
            "zone",
            "dnssec",
            "keys",
            "import",
            &zone_name,
            "--key",
            &key_file,
            "--private",
            &private_file,
            "--policy",
            &split_policy,
        ])
        .await;
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("does not match policy"), "{stderr}");

    let imported = app
        .run_cli_success(&[
            "zone",
            "dnssec",
            "keys",
            "import",
            &zone_name,
            "--key",
            &key_file,
            "--private",
            &private_file,
        ])
        .await;
    assert!(
        imported.contains("DNSSEC key imported successfully"),
        "{imported}"
    );
    assert!(imported.contains(&key_tag), "{imported}");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_split_key_import_restores_both_roles() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-split.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let policy_name = format!("{}-split", app.namespace());
    app.run_cli_success(&[
        "dnssec-policy",
        "create",
        "--name",
        &policy_name,
        "--split-keys",
    ])
    .await;
    app.run_cli_success(&[
        "zone",
        "dnssec",
        "enable",
        &zone_name,
        "--policy",
        &policy_name,
    ])
    .await;

    let exported = app
        .run_cli_success(&["zone", "dnssec", "keys", "export", &zone_name])
        .await;
    // The stream alternates `; K*.key (role, tag N)` and `; K*.private`
    // headers; carve it into per-header blocks.
    let mut sections: Vec<(String, String)> = Vec::new();
    for line in exported.lines() {
        if line.starts_with("; K") {
            sections.push((line.to_string(), String::new()));
        } else if let Some((_, body)) = sections.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    assert_eq!(sections.len(), 4, "{exported}");

    let dir = tempfile::tempdir().expect("create key dir");
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for chunk in sections.chunks(2) {
        let (key_header, key_body) = &chunk[0];
        let (_, private_body) = &chunk[1];
        let role = if key_header.contains("(ksk,") {
            "ksk"
        } else {
            "zsk"
        };
        let key_file = dir.path().join(format!("{role}.key"));
        let private_file = dir.path().join(format!("{role}.private"));
        std::fs::write(&key_file, key_body).expect("write .key");
        std::fs::write(&private_file, private_body).expect("write .private");
        pairs.push((
            role.to_string(),
            key_file.to_str().expect("utf-8 temp dir").to_string(),
            private_file.to_str().expect("utf-8 temp dir").to_string(),
        ));
    }
    pairs.sort(); // ksk before zsk

    app.run_cli_success(&["zone", "dnssec", "disable", &zone_name])
        .await;

    // Both halves arrive in one call: a KSK alone could not sign, so the
    // import takes the complete set.
    let (role, ksk_key, ksk_private) = &pairs[0];
    assert_eq!(role, "ksk");
    let (_, zsk_key, zsk_private) = &pairs[1];
    let imported = app
        .run_cli_success(&[
            "zone",
            "dnssec",
            "keys",
            "import",
            &zone_name,
            "--key",
            ksk_key,
            "--private",
            ksk_private,
            "--key",
            zsk_key,
            "--private",
            zsk_private,
            "--policy",
            &policy_name,
        ])
        .await;
    assert!(imported.contains("DNSSEC enabled"), "{imported}");
    assert!(imported.contains("IN DS"), "{imported}");

    let signed_export = app
        .run_cli_success(&["zone", "export", &zone_name, "--signed"])
        .await;
    assert!(
        signed_export.contains("\tIN\tRRSIG\tSOA "),
        "{signed_export}"
    );
    assert!(
        signed_export.contains("\tIN\tDNSKEY\t257 3 ")
            && signed_export.contains("\tIN\tDNSKEY\t256 3 "),
        "{signed_export}"
    );
}
