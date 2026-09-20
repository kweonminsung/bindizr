use crate::{cli::common::summary_row, common::TestApp};

/// Verify zone-file export through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_export_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("export.example");
    // Zone TTL is deliberately not 3600 so an inherited TTL is distinguishable.
    app.create_zone_cli(&zone_name, "7200").await;
    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.1",
        "--ttl",
        "300",
    ])
    .await;

    // An omitted TTL is fixed to the zone's TTL (7200) at write time.
    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "nottl",
        "--type",
        "A",
        "--value",
        "192.0.2.2",
    ])
    .await;

    let exported = app.run_cli_success(&["zone", "export", &zone_name]).await;
    assert!(
        exported.contains(&format!("$ORIGIN {zone_name}.")),
        "{exported}"
    );
    assert!(exported.contains("$TTL 7200"), "{exported}");
    assert!(exported.contains("IN\tSOA\t"), "{exported}");
    assert!(
        exported.contains("www\t300\tIN\tA\t192.0.2.1"),
        "{exported}"
    );
    assert!(
        exported.contains("nottl\t7200\tIN\tA\t192.0.2.2"),
        "{exported}"
    );

    // Re-importing the export into the same zone changes nothing.
    let reimport = app
        .run_cli_success_with_input(&["zone", "import", &zone_name, "-"], &exported)
        .await;
    assert_eq!(summary_row(&reimport)[1..3], ["0", "0"], "{reimport}");
}

/// Verify that zone export orders by name then type then RDATA.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_export_orders_by_name_then_type_then_rdata() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("export-order.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // Fed in deliberately unsorted; rows also come back from the DB in no
    // guaranteed order, so the export's own sort is what the assertion pins.
    app.run_cli_success_with_input(
        &["zone", "import", &zone_name, "-"],
        "b IN A 192.0.2.2\n\
         a IN TXT \"zzz\"\n\
         a IN A 192.0.2.10\n\
         a IN A 192.0.2.2\n\
         a IN MX 10 mail.example.com.\n",
    )
    .await;

    let exported = app.run_cli_success(&["zone", "export", &zone_name]).await;
    let ordered: Vec<&str> = exported
        .lines()
        .filter(|l| l.starts_with("a\t") || l.starts_with("b\t"))
        .collect();

    // Rdata ties break as text, so 192.0.2.10 sorts before 192.0.2.2.
    assert_eq!(
        ordered,
        vec![
            "a\t3600\tIN\tA\t192.0.2.10",
            "a\t3600\tIN\tA\t192.0.2.2",
            "a\t3600\tIN\tMX\t10 mail.example.com.",
            "a\t3600\tIN\tTXT\t\"zzz\"",
            "b\t3600\tIN\tA\t192.0.2.2",
        ],
        "{exported}"
    );
}
