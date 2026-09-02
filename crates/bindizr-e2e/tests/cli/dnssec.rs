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
    // DNSKEY`; an active key's ELIGIBLE-AT renders as `-`.
    let key_row = status
        .lines()
        .find(|line| line.contains("ecdsap256sha256"))
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

    let timing = app
        .run_cli_success(&[
            "zone",
            "dnssec",
            "timing",
            &zone_name,
            "--signature-validity-days",
            "30",
            "--zsk-lifetime-days",
            "90",
        ])
        .await;
    assert!(timing.contains("DNSSEC timing updated successfully"));
    assert!(
        timing.contains("validity 30d") && timing.contains("zsk-lifetime 90d"),
        "{timing}"
    );
    assert!(timing.contains("overridden"), "{timing}");

    // The call replaces the overrides, so an omitted knob reverts.
    let reverted = app
        .run_cli_success(&["zone", "dnssec", "timing", &zone_name])
        .await;
    assert!(!reverted.contains("overridden"), "{reverted}");

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

    let enabled = app
        .run_cli_success(&["zone", "dnssec", "enable", &zone_name, "--denial", "nsec3"])
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
        .find(|line| line.contains("ecdsap256sha256"))
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
    app.run_cli_success(&["zone", "dnssec", "enable", &zone_name, "--split-keys"])
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

    // The lone KSK cannot sign the zone yet; the import must stage it.
    let (role, key_file, private_file) = &pairs[0];
    assert_eq!(role, "ksk");
    let staged = app
        .run_cli_success(&[
            "zone",
            "dnssec",
            "keys",
            "import",
            &zone_name,
            "--key",
            key_file,
            "--private",
            private_file,
            "--role",
            "ksk",
        ])
        .await;
    assert!(
        staged.contains("DNSSEC key imported successfully"),
        "{staged}"
    );

    // The ZSK completes the pair and the zone signs.
    let (_, key_file, private_file) = &pairs[1];
    app.run_cli_success(&[
        "zone",
        "dnssec",
        "keys",
        "import",
        &zone_name,
        "--key",
        key_file,
        "--private",
        private_file,
    ])
    .await;

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
