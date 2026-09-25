use crate::{
    cli::common::{read_dnssec_status, read_signing_key_tag},
    common::TestApp,
};

/// Each key's `(tag, state)` from `dnssec status`, sorted so two runs compare.
async fn read_key_states(app: &TestApp, zone_name: &str) -> Vec<(u64, String)> {
    let mut states: Vec<(u64, String)> = read_dnssec_status(app, zone_name).await["keys"]
        .as_array()
        .expect("status lists the keys")
        .iter()
        .map(|key| {
            (
                key["key_tag"].as_u64().expect("key tag"),
                key["state"].as_str().expect("key state").to_string(),
            )
        })
        .collect();
    states.sort();
    states
}

/// Split `dnssec keys export` into the `K*.key`/`K*.private` file pairs on
/// disk that the import takes.
async fn write_exported_pairs(
    app: &TestApp,
    zone_name: &str,
    dir: &std::path::Path,
) -> Vec<(String, String)> {
    let exported = app
        .run_cli_success(&["dnssec", "keys", "export", zone_name])
        .await;
    let mut blocks: Vec<String> = Vec::new();
    for line in exported.lines() {
        if line.starts_with("; K") {
            blocks.push(String::new());
        } else if let Some(body) = blocks.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }

    let mut pairs = Vec::new();
    for (index, chunk) in blocks.chunks(2).enumerate() {
        let key_file = dir.join(format!("{index}.key"));
        let private_file = dir.join(format!("{index}.private"));
        std::fs::write(&key_file, &chunk[0]).expect("write .key");
        std::fs::write(&private_file, &chunk[1]).expect("write .private");
        pairs.push((
            key_file.to_str().expect("utf-8 temp dir").to_string(),
            private_file.to_str().expect("utf-8 temp dir").to_string(),
        ));
    }
    pairs
}

/// Verify DNSSEC key export and import through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_key_export_import_round_trip_via_cli() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-keys.example");
    app.create_zone_cli(&zone_name, "3600").await;
    app.run_cli_success(&[
        "dnssec",
        "enable",
        &zone_name,
        "--parent-ns-addrs",
        "127.0.0.1:9",
    ])
    .await;

    let key_tag = read_signing_key_tag(&app, &zone_name).await;

    let exported = app
        .run_cli_success(&["dnssec", "keys", "export", &zone_name])
        .await;
    let base = format!("K{zone_name}.+013+{key_tag:05}");
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
    app.run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"])
        .await;

    // Under a split-key policy the lone SEP key is a KSK with no ZSK, so the
    // import is refused before anything is stored.
    let split_policy = format!("{}-split", app.namespace());
    app.run_cli_success(&["dnssec-policy", "create", &split_policy, "--split-keys"])
        .await;
    let refused = app
        .run_cli(&[
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
    assert!(imported.contains(&key_tag.to_string()), "{imported}");
}

/// Verify that zone DNSSEC split key import restores both roles.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_split_key_import_restores_both_roles() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-split.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let policy_name = format!("{}-split", app.namespace());
    app.run_cli_success(&["dnssec-policy", "create", &policy_name, "--split-keys"])
        .await;
    app.run_cli_success(&[
        "dnssec",
        "enable",
        &zone_name,
        "--policy",
        &policy_name,
        "--parent-ns-addrs",
        "127.0.0.1:9",
    ])
    .await;

    let exported = app
        .run_cli_success(&["dnssec", "keys", "export", &zone_name])
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

    app.run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"])
        .await;

    // Both halves arrive in one call: a KSK alone could not sign, so the
    // import takes the complete set.
    let (role, ksk_key, ksk_private) = &pairs[0];
    assert_eq!(role, "ksk");
    let (_, zsk_key, zsk_private) = &pairs[1];
    let imported = app
        .run_cli_success(&[
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

/// Verify that a zone exported mid rollover imports still mid rollover.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_zone_exported_mid_rollover_imports_still_mid_rollover() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-rolling.example");
    app.create_zone_cli(&zone_name, "3600").await;
    app.run_cli_success(&[
        "dnssec",
        "enable",
        &zone_name,
        "--parent-ns-addrs",
        "127.0.0.1:9",
    ])
    .await;
    app.run_cli_success(&["dnssec", "rollover", "start", &zone_name])
        .await;

    let before = read_key_states(&app, &zone_name).await;
    assert_eq!(before.len(), 2, "{before:?}");
    assert!(
        before.iter().any(|(_, state)| state == "active"),
        "{before:?}"
    );
    assert!(
        before.iter().any(|(_, state)| state == "published"),
        "{before:?}"
    );

    let dir = tempfile::tempdir().expect("create key dir");
    let pairs = write_exported_pairs(&app, &zone_name, dir.path()).await;
    assert_eq!(pairs.len(), 2, "a rollover exports both keys");

    app.run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"])
        .await;
    let mut args = vec!["dnssec", "keys", "import", zone_name.as_str()];
    for (key_file, private_file) in &pairs {
        args.extend(["--key", key_file, "--private", private_file]);
    }
    app.run_cli_success(&args).await;

    // Without the timing BIND writes into the private files, both keys would
    // land active and the rollover would be gone.
    assert_eq!(read_key_states(&app, &zone_name).await, before);
    let refused = app
        .run_cli(&["dnssec", "rollover", "start", &zone_name])
        .await;
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("rollover"), "{stderr}");
}
