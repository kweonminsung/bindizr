//! Prerequisites read the same signed zone contents that DNS serves.

use domain::base::Rtype;
use reqwest::{Method, StatusCode};
use serde_json::json;

use super::{
    common::{exported_record_sets, unsigned_nsupdate_app},
    *,
};

/// Check derived names and RRsets for existence (RFC 2136, Sections 3.2.1–3.2.2).
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_see_derived_records() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({"parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&limit=1000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;
    let add = [UpdateRecord::AddA {
        name: format!("must-not-exist.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.140".to_string(),
    }];
    let derived: Vec<_> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["id"].is_null())
        .collect();
    assert!(derived.iter().any(|row| row["type"] == "DNSKEY"));
    assert!(derived.iter().any(|row| row["type"] == "NSEC3"));
    for row in derived {
        let name = row["name"].as_str().unwrap().to_string();
        let rtype: Rtype = row["type"].as_str().unwrap().parse().unwrap();
        for (prerequisite, expected) in [
            (
                PrereqRecord::RecordSetInUse {
                    name: name.clone(),
                    rtype,
                },
                Rcode::NOERROR,
            ),
            (
                PrereqRecord::RecordSetNotInUse {
                    name: name.clone(),
                    rtype,
                },
                Rcode::YXRRSET,
            ),
            (
                PrereqRecord::NameInUse { name: name.clone() },
                Rcode::NOERROR,
            ),
            (PrereqRecord::NameNotInUse { name }, Rcode::YXDOMAIN),
        ] {
            let updates = if expected == Rcode::NOERROR {
                &[][..]
            } else {
                &add
            };
            let rcode = send_update_udp(app.dns_port(), zone_name, &[prerequisite], updates, None)
                .expect("prerequisite response");
            assert_eq!(rcode, expected, "{row}");
            assert_eq!(app.list_records(zone_name).await, before);
            assert_eq!(app.read_zone_serial(zone_name).await, serial);
        }
    }
}

/// Check RRset equality with NSEC/NSEC3 and split keys (RFC 2136, Section 3.2.3).
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_compare_whole_served_record_sets() {
    for denial in ["nsec", "nsec3"] {
        let app = unsigned_nsupdate_app().await;
        let zone = app.create_test_zone().await;
        let zone_name = zone["name"].as_str().unwrap();
        // Exercise different stored encodings through the same wire comparison.
        for mut record in [
            json!({"name": "v6", "type": "AAAA", "value": "2001:db8::1"}),
            json!({"name": "txt", "type": "TXT", "value": "\"First\" \"second\""}),
            json!({"name": "mail", "type": "MX", "value": "Mail.Example.NET.", "priority": 10}),
            json!({"name": "alias", "type": "CNAME", "value": "Target.Example.NET."}),
            json!({"name": "caa", "type": "CAA", "value": "0 issue \"ca.example\""}),
        ] {
            record["zone_name"] = json!(zone_name);
            let (status, body) = app
                .send_request(Method::POST, "/records", Some(record))
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        let policy_name = format!("{}-prereq", app.namespace());
        let (status, body) = app
            .send_request(
                Method::POST,
                "/dnssec-policies",
                Some(json!({
                    "name": policy_name, "denial": denial, "split_keys": true,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/dnssec"),
                Some(json!({
                    "policy_name": policy_name, "parent_ns_addrs": ["127.0.0.1:9"],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let sets = exported_record_sets(&app, zone_name).await;
        let apex = format!("{zone_name}.");
        for rtype in [
            Rtype::DNSKEY,
            Rtype::RRSIG,
            Rtype::CDS,
            Rtype::CDNSKEY,
            Rtype::SOA,
            Rtype::NS,
        ] {
            assert!(
                sets.contains_key(&(apex.clone(), rtype)),
                "missing {rtype}: {sets:?}"
            );
        }
        let denial_type = if denial == "nsec" {
            Rtype::NSEC
        } else {
            Rtype::NSEC3
        };
        assert!(sets.keys().any(|(_, rtype)| *rtype == denial_type));
        assert!(sets[&(apex.clone(), Rtype::DNSKEY)].len() > 1);
        let serial = app.read_zone_serial(zone_name).await;
        for ((name, rtype), values) in &sets {
            let prerequisites: Vec<_> = values
                .iter()
                .map(|rdata| PrereqRecord::RecordEquals {
                    name: name.clone(),
                    rtype: *rtype,
                    rdata: rdata.clone(),
                })
                .collect();
            let rcode = send_update_udp(app.dns_port(), zone_name, &prerequisites, &[], None)
                .expect("exact set");
            assert_eq!(rcode, Rcode::NOERROR, "{name} {rtype}");
            let mut repeated = prerequisites.clone();
            repeated.reverse();
            repeated.extend(prerequisites.clone());
            let rcode = send_update_udp(app.dns_port(), zone_name, &repeated, &[], None)
                .expect("repeated set");
            assert_eq!(rcode, Rcode::NOERROR, "{name} {rtype}");
            if prerequisites.len() > 1 {
                let rcode =
                    send_update_udp(app.dns_port(), zone_name, &prerequisites[..1], &[], None)
                        .expect("subset");
                assert_eq!(rcode, Rcode::NXRRSET, "{name} {rtype}");
            }
        }
        // A different DNSKEY remains well-formed but must fail equality.
        let values = &sets[&(apex.clone(), Rtype::DNSKEY)];
        let mut wrong = values.clone();
        *wrong[0].last_mut().unwrap() ^= 1;
        for values in [
            wrong.clone(),
            values.iter().chain(&wrong[..1]).cloned().collect(),
        ] {
            let prerequisites: Vec<_> = values
                .into_iter()
                .map(|rdata| PrereqRecord::RecordEquals {
                    name: apex.clone(),
                    rtype: Rtype::DNSKEY,
                    rdata,
                })
                .collect();
            let rcode = send_update_udp(app.dns_port(), zone_name, &prerequisites, &[], None)
                .expect("different set");
            assert_eq!(rcode, Rcode::NXRRSET);
        }
        // Read-only checks must not advance the signed view.
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
        assert_eq!(exported_record_sets(&app, zone_name).await, sets);

        // Re-signing must make the old RRSIG prerequisite fail.
        let signatures: Vec<_> = sets[&(apex.clone(), Rtype::RRSIG)]
            .iter()
            .map(|rdata| PrereqRecord::RecordEquals {
                name: apex.clone(),
                rtype: Rtype::RRSIG,
                rdata: rdata.clone(),
            })
            .collect();
        let add = |owner: &str| UpdateRecord::AddA {
            name: format!("{owner}.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.141".to_string(),
        };
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &signatures,
            &[add("accepted")],
            None,
        )
        .expect("guarded write");
        assert_eq!(rcode, Rcode::NOERROR);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
        let after = exported_record_sets(&app, zone_name).await;
        assert_ne!(
            after[&(apex.clone(), Rtype::RRSIG)],
            sets[&(apex.clone(), Rtype::RRSIG)]
        );
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &signatures,
            &[add("rejected")],
            None,
        )
        .expect("stale guard");
        assert_eq!(rcode, Rcode::NXRRSET);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
        assert_eq!(exported_record_sets(&app, zone_name).await, after);
    }
}

/// Check derived read grants and signed TCP errors.
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_require_read_grants_and_sign_errors() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({
                "parent_ns_addrs": ["127.0.0.1:9"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let key = create_tsig_key(&app, "dnssec-prereq", KeyRole::Own).await;
    app.run_cli_success(&[
        "role",
        "grant",
        &key.name,
        "--zone",
        zone_name,
        "--actions",
        "record:read",
        "--types",
        "A",
    ])
    .await;
    let apex = format!("{zone_name}.");
    let sets = exported_record_sets(&app, zone_name).await;
    let values = &sets[&(apex.clone(), Rtype::DNSKEY)];
    let prerequisites: Vec<_> = values
        .iter()
        .map(|rdata| PrereqRecord::RecordEquals {
            name: apex.clone(),
            rtype: Rtype::DNSKEY,
            rdata: rdata.clone(),
        })
        .collect();
    let rcode = send_update_tcp(app.dns_port(), zone_name, &prerequisites, &[], Some(&key))
        .expect("restricted read");
    assert_eq!(rcode, Rcode::REFUSED);
    app.run_cli_success(&[
        "role",
        "grant",
        &key.name,
        "--zone",
        zone_name,
        "--actions",
        "record:read",
    ])
    .await;
    let rcode = send_update_tcp(app.dns_port(), zone_name, &prerequisites, &[], Some(&key))
        .expect("granted read");
    assert_eq!(rcode, Rcode::NOERROR);
    for (rtype, rdata, expected) in [
        (Rtype::DNSKEY, vec![1, 1, 3], Rcode::FORMERR),
        (Rtype::from_int(65280), vec![], Rcode::NXRRSET),
    ] {
        let prerequisite = PrereqRecord::RecordEquals {
            name: apex.clone(),
            rtype,
            rdata,
        };
        let rcode = send_update_tcp(app.dns_port(), zone_name, &[prerequisite], &[], Some(&key))
            .expect("signed error");
        assert_eq!(rcode, expected);
    }
    assert_eq!(exported_record_sets(&app, zone_name).await, sets);
}
