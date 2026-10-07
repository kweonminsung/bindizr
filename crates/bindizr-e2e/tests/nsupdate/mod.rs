use domain::base::{Rtype, iana::Rcode};
use serde_json::Value;
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions,
    dns::nsupdate::{
        KeyRole, PrereqRecord, UpdateRecord, create_tsig_key, send_signed_update, send_update,
    },
};

/// These drive bindizr's own DNS listener over UDP with unsigned updates, so
/// the whole RFC 2136 path runs: message decoding, prerequisites, the apply
/// transaction, and the serial bump. Signed updates below also exercise grants.
async fn unsigned_nsupdate_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        nsupdate_tsig_required: false,
        ..TestAppOptions::default()
    })
    .await
}

/// Verify that `nsupdate` adds and deletes records.
#[tokio::test]
#[serial]
async fn nsupdate_adds_and_deletes_records() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("www.{zone_name}.");
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("add update");
    assert_eq!(rcode, Rcode::NOERROR);

    let records = app.list_records(&zone_name).await;
    assert!(
        records
            .iter()
            .any(|record| record["name"] == format!("www.{zone_name}.")
                && record["type"] == "A"
                && record["value"] == "192.0.2.10"),
        "record was not added: {records:#?}"
    );

    // A second identical add is a silent no-op (RFC 2136, Section 3.4.2.2).
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("duplicate add");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), records.len());

    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::DeleteA {
            name: owner.clone(),
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("delete update");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        !app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["value"] == "192.0.2.10"),
        "record was not deleted"
    );
    let (status, history) = app
        .send_request(
            reqwest::Method::GET,
            &format!("/zones/{zone_name}/versions"),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{history}");
    assert_eq!(
        history["items"][0]["change_source"], "nsupdate",
        "{history}"
    );
    assert!(
        history["items"][0].get("changed_by").unwrap().is_null(),
        "{history}"
    );
}

/// Verify that nsupdate deletes every record of a name and type.
#[tokio::test]
#[serial]
async fn nsupdate_deletes_every_record_of_a_name_and_type() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-records.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("multi.{zone_name}.");
    for addr in ["192.0.2.20", "192.0.2.21"] {
        send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: addr.to_string(),
            }],
        )
        .expect("add update");
    }

    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::DeleteRecordSet {
            name: owner.clone(),
            rtype: Rtype::A,
        }],
    )
    .expect("delete every record of the name and type");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        !app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("multi.{zone_name}.")),
        "records were not deleted"
    );
}

/// Verify that nsupdate applies nothing when a prerequisite fails.
#[tokio::test]
#[serial]
async fn nsupdate_applies_nothing_when_a_prerequisite_fails() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-prereq.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let before = app.list_records(&zone_name).await.len();
    let owner = format!("guarded.{zone_name}.");

    // The owner does not exist, so a "must exist" prerequisite fails.
    let rcode = send_update(
        port,
        &zone_name,
        &[PrereqRecord::NameInUse {
            name: owner.clone(),
        }],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
    )
    .expect("failing prerequisite");
    assert_eq!(rcode, Rcode::NXDOMAIN);
    assert_eq!(app.list_records(&zone_name).await.len(), before);

    // The matching "must not exist" prerequisite lets the same update through.
    let rcode = send_update(
        port,
        &zone_name,
        &[PrereqRecord::NameNotInUse {
            name: owner.clone(),
        }],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
    )
    .expect("passing prerequisite");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), before + 1);
}

/// Verify that a value prerequisite needs every record of the name and type.
#[tokio::test]
#[serial]
async fn a_value_prerequisite_needs_every_record_of_the_name_and_type() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-records.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("check.{zone_name}.");
    for addr in ["192.0.2.1", "192.0.2.2"] {
        let rcode = send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: addr.to_string(),
            }],
        )
        .expect("seed the records");
        assert_eq!(rcode, Rcode::NOERROR);
    }
    let before = app.list_records(&zone_name).await.len();
    let update = [UpdateRecord::AddA {
        name: format!("subset.{zone_name}."),
        ttl: 60,
        addr: "192.0.2.99".to_string(),
    }];

    // RFC 2136, Section 3.2.3: the prerequisite record set must equal the zone's,
    // so naming one of its two values is NXRRSET and applies nothing.
    let rcode = send_update(
        port,
        &zone_name,
        &[PrereqRecord::AEquals {
            name: owner.clone(),
            addr: "192.0.2.1".to_string(),
        }],
        &update,
    )
    .expect("subset prerequisite");
    assert_eq!(rcode, Rcode::NXRRSET);
    assert_eq!(app.list_records(&zone_name).await.len(), before);

    // Both values, in either order, are the whole record set.
    let rcode = send_update(
        port,
        &zone_name,
        &[
            PrereqRecord::AEquals {
                name: owner.clone(),
                addr: "192.0.2.2".to_string(),
            },
            PrereqRecord::AEquals {
                name: owner.clone(),
                addr: "192.0.2.1".to_string(),
            },
        ],
        &update,
    )
    .expect("whole prerequisite");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), before + 1);
}

/// Verify that `nsupdate` refuses an owner outside the zone.
#[tokio::test]
#[serial]
async fn nsupdate_refuses_an_owner_outside_the_zone() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-notzone.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let rcode = send_update(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: "www.elsewhere.example.".to_string(),
            ttl: 300,
            addr: "192.0.2.40".to_string(),
        }],
    )
    .expect("out-of-zone update");

    assert_eq!(rcode, Rcode::NOTZONE);
}

/// Verify that nsupdate advances the zone serial once per message.
#[tokio::test]
#[serial]
async fn nsupdate_advances_the_zone_serial_once_per_message() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-serial.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let before = app.read_zone_serial(&zone_name).await;

    let owner = format!("pair.{zone_name}.");
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[
            UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.50".to_string(),
            },
            UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.51".to_string(),
            },
        ],
    )
    .expect("two-record update");
    assert_eq!(rcode, Rcode::NOERROR);

    assert_eq!(app.read_zone_serial(&zone_name).await, before + 1);

    // An update that changes nothing must leave the serial alone, or every
    // no-op would make secondaries re-transfer.
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::DeleteA {
            name: owner,
            addr: "198.51.100.1".to_string(),
        }],
    )
    .expect("no-op update");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.read_zone_serial(&zone_name).await, before + 1);
}

/// Verify that a signed update requires a zone grant for its TSIG key.
///
/// The unsigned cases exercise address authorization; this case checks the key-based path.
#[tokio::test]
#[serial]
async fn signed_nsupdate_needs_a_grant_for_the_zone() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("nsupdate-policy.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();
    let key = create_tsig_key(&app, "nsupdate-policy-key", KeyRole::Own).await;

    let add = |owner: String| UpdateRecord::AddA {
        name: owner,
        ttl: 300,
        addr: "192.0.2.60".to_string(),
    };

    // No grant gives this key anything in the zone.
    let rcode = send_signed_update(
        port,
        &zone_name,
        &[],
        &[add(format!("a.{zone_name}."))],
        &key,
    )
    .expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // Granting only `a` leaves every other owner name refused.
    app.run_cli_success(&[
        "role",
        "grant",
        &key.name,
        "--zone",
        &zone_name,
        "--actions",
        "record:create",
        "--pattern",
        "a",
    ])
    .await;

    let rcode = send_signed_update(
        port,
        &zone_name,
        &[],
        &[add(format!("b.{zone_name}."))],
        &key,
    )
    .expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    let rcode = send_signed_update(
        port,
        &zone_name,
        &[],
        &[add(format!("a.{zone_name}."))],
        &key,
    )
    .expect("send");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("a.{zone_name}.")),
        "granted update was not applied"
    );

    // An add is `record:create`; deleting what it added is a separate action.
    let delete = UpdateRecord::DeleteA {
        name: format!("a.{zone_name}."),
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_signed_update(port, &zone_name, &[], &[delete], &key).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // The DNS plane has no API token, so the key that signed the update is
    // the name the change is recorded under.
    let (status, body) = app
        .send_request(
            reqwest::Method::GET,
            &format!("/zones/{zone_name}/versions"),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["change_source"], "nsupdate", "{body}");
    assert_eq!(
        body["items"][0]["changed_by"],
        serde_json::json!({"kind": "tsig_key", "name": key.name}),
        "{body}"
    );
}

/// Verify that a signed prerequisite needs a grant reaching what it names.
#[tokio::test]
#[serial]
async fn a_signed_prerequisite_needs_a_grant_reaching_what_it_names() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("nsupdate-prereq.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();
    let key = create_tsig_key(&app, "nsupdate-prereq-key", KeyRole::Own).await;
    app.run_cli_success(&[
        "role",
        "grant",
        &key.name,
        "--zone",
        &zone_name,
        "--actions",
        "record:read,record:create",
        "--pattern",
        "*.dyn",
        "--types",
        "A",
    ])
    .await;

    // The answer must not depend on whether `secret` exists.
    let secret = || PrereqRecord::NameNotInUse {
        name: format!("secret.{zone_name}."),
    };
    let rcode = send_signed_update(port, &zone_name, &[secret()], &[], &key).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    let (status, body) = app
        .send_request(
            reqwest::Method::POST,
            "/records",
            Some(serde_json::json!({
                "name": "secret",
                "type": "A",
                "value": "192.0.2.1",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
    let rcode = send_signed_update(port, &zone_name, &[secret()], &[], &key).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // Inside the grant the prerequisite is answered, before and after the add.
    let host = format!("host.dyn.{zone_name}.");
    let equals = || PrereqRecord::AEquals {
        name: host.clone(),
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_signed_update(port, &zone_name, &[equals()], &[], &key).expect("send");
    assert_eq!(rcode, Rcode::NXRRSET);
    let add = UpdateRecord::AddA {
        name: host.clone(),
        ttl: 300,
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_signed_update(port, &zone_name, &[], &[add], &key).expect("send");
    assert_eq!(rcode, Rcode::NOERROR);
    let rcode = send_signed_update(port, &zone_name, &[equals()], &[], &key).expect("send");
    assert_eq!(rcode, Rcode::NOERROR);
}

/// Verify that dynamic updates map the input apex `@` to the empty stored owner.
#[tokio::test]
#[serial]
async fn nsupdate_adds_at_the_zone_apex() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-apex.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let rcode = send_update(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: format!("{zone_name}."),
            ttl: 300,
            addr: "192.0.2.60".to_string(),
        }],
    )
    .expect("apex add");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("{zone_name}.")
                && record["type"] == "A"
                && record["value"] == "192.0.2.60"),
        "apex record was not added"
    );
}

/// Verify that an update for a zone this server does not serve is NOTAUTH
/// (RFC 2136, Section 3.1.2), while an owner outside a served zone stays
/// NOTZONE.
#[tokio::test]
#[serial]
async fn nsupdate_answers_notauth_for_a_zone_it_does_not_serve() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-notauth.example");

    let rcode = send_update(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: format!("host.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.70".to_string(),
        }],
    )
    .expect("update for an unknown zone");

    assert_eq!(rcode, Rcode::NOTAUTH);
}

/// Verify that a delete leaves the apex NS set standing and passes over the
/// SOA (RFC 2136, Sections 3.4.2.3 and 3.4.2.4).
#[tokio::test]
#[serial]
async fn nsupdate_keeps_the_apex_ns_set() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-apex-ns.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let apex = format!("{zone_name}.");
    let apex_ns = |records: &[Value]| -> Vec<String> {
        records
            .iter()
            .filter(|record| record["name"] == apex && record["type"] == "NS")
            .map(|record| record["value"].as_str().unwrap().to_string())
            .collect()
    };
    let seeded = apex_ns(&app.list_records(&zone_name).await);
    assert_eq!(seeded.len(), 1, "zone creation seeds one apex NS");

    // The NS set survives a delete of the type, of the only NS, and of the
    // whole name; the SOA delete is passed over rather than refused.
    let apex_a = UpdateRecord::AddA {
        name: apex.clone(),
        ttl: 300,
        addr: "192.0.2.80".to_string(),
    };
    for updates in [
        vec![UpdateRecord::DeleteRecordSet {
            name: apex.clone(),
            rtype: Rtype::NS,
        }],
        vec![UpdateRecord::DeleteNs {
            name: apex.clone(),
            target: seeded[0].clone(),
        }],
        vec![UpdateRecord::DeleteRecordSet {
            name: apex.clone(),
            rtype: Rtype::SOA,
        }],
        vec![
            apex_a,
            UpdateRecord::DeleteRecordSet {
                name: apex.clone(),
                rtype: Rtype::ANY,
            },
        ],
    ] {
        let rcode = send_update(app.dns_port(), &zone_name, &[], &updates).expect("apex delete");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }

    let records = app.list_records(&zone_name).await;
    assert_eq!(apex_ns(&records), seeded);
    assert!(
        !records
            .iter()
            .any(|record| record["name"] == apex && record["type"] == "A"),
        "the whole-name delete removed the apex A"
    );
}

/// Verify that a CNAME beside other data, or data beside a CNAME, is passed
/// over, and that a second CNAME replaces the first (RFC 2136, Section
/// 3.4.2.2).
#[tokio::test]
#[serial]
async fn nsupdate_passes_over_a_cname_conflict_and_replaces_a_cname() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let www = format!("www.{zone_name}.");
    let alias = format!("alias.{zone_name}.");
    let records_at = |records: &[Value], name: &str| -> Vec<(String, String)> {
        records
            .iter()
            .filter(|record| record["name"] == name)
            .map(|record| {
                (
                    record["type"].as_str().unwrap().to_string(),
                    record["value"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };

    for updates in [
        vec![UpdateRecord::AddA {
            name: www.clone(),
            ttl: 300,
            addr: "192.0.2.90".to_string(),
        }],
        // A CNAME beside the A: passed over.
        vec![UpdateRecord::AddCname {
            name: www.clone(),
            ttl: 300,
            target: format!("target.{zone_name}."),
        }],
        vec![UpdateRecord::AddCname {
            name: alias.clone(),
            ttl: 300,
            target: format!("one.{zone_name}."),
        }],
        // An A beside the CNAME: passed over.
        vec![UpdateRecord::AddA {
            name: alias.clone(),
            ttl: 300,
            addr: "192.0.2.91".to_string(),
        }],
        // A second CNAME replaces the first.
        vec![UpdateRecord::AddCname {
            name: alias.clone(),
            ttl: 300,
            target: format!("two.{zone_name}."),
        }],
    ] {
        let rcode = send_update(app.dns_port(), zone_name, &[], &updates).expect("update");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }

    let records = app.list_records(zone_name).await;
    assert_eq!(
        records_at(&records, &www),
        [("A".to_string(), "192.0.2.90".to_string())]
    );
    assert_eq!(
        records_at(&records, &alias),
        [("CNAME".to_string(), format!("two.{zone_name}."))]
    );
}

/// Verify that an add with a new TTL moves the whole record set to it, as
/// RFC 2181, Section 5.2 keeps one TTL per set.
#[tokio::test]
#[serial]
async fn nsupdate_moves_a_record_set_to_the_added_ttl() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let host = format!("host.{zone_name}.");

    for (ttl, addr) in [
        (300, "192.0.2.100"),
        (600, "192.0.2.101"),
        (900, "192.0.2.100"),
    ] {
        let rcode = send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: host.clone(),
                ttl,
                addr: addr.to_string(),
            }],
        )
        .expect("add");
        assert_eq!(rcode, Rcode::NOERROR);
    }

    // The third add repeated an rdata with yet another TTL: the set follows.
    let ttls: Vec<u64> = app
        .list_records(zone_name)
        .await
        .iter()
        .filter(|record| record["name"] == host)
        .map(|record| record["ttl"].as_u64().unwrap())
        .collect();
    assert_eq!(ttls, [900, 900]);
}
