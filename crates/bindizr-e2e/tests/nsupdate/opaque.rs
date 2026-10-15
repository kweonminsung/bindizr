//! RFC 3597 and arbitrary DNS octets through UPDATE, prerequisites and export.

use domain::base::{Rtype, iana::Rcode};

use super::common::exported_record_sets;
use crate::common::{
    TestApp,
    dns::{
        nsupdate::{PrerequisiteRecord, UpdateRecord, send_update_udp},
        tsig::{KeyRole, create_tsig_key},
    },
};

/// Preserve binary owners, TXT segment octets, zero-length unknown values and RDATA case.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn update_preserves_opaque_values_and_names() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "opaque-key", KeyRole::Admin).await;
    let target = crate::common::dns::parse_name("Mixed.Example.")
        .unwrap()
        .as_slice()
        .to_vec();
    for (label, rtype, rdata) in [
        (r"\255\032", Rtype::TXT, vec![1, 255, 1, 0]),
        ("split", Rtype::TXT, vec![1, 0xc3, 1, 0xa9]),
        ("empty", Rtype::from_int(65280), vec![]),
        ("opaque", Rtype::from_int(65281), vec![0, 255, 192, 12]),
        (
            "srv",
            Rtype::SRV,
            [vec![0, 1, 0, 2, 0, 80], target.clone()].concat(),
        ),
        ("dname", Rtype::DNAME, target),
    ] {
        let owner = format!("{label}.{zone}.");
        let export_owner = format!("{}.", crate::common::dns::parse_name(&owner).unwrap());
        assert_eq!(
            send_update_udp(
                app.dns_port(),
                zone,
                &[],
                &[UpdateRecord::AddRecord {
                    name: owner.clone(),
                    rtype,
                    ttl: 300,
                    rdata: rdata.clone()
                }],
                Some(&key)
            )
            .unwrap(),
            Rcode::NOERROR
        );
        let exported = exported_record_sets(&app, zone).await;
        assert_eq!(
            exported.get(&(export_owner.clone(), rtype)).unwrap(),
            &vec![rdata.clone()]
        );
        assert_eq!(
            send_update_udp(
                app.dns_port(),
                zone,
                &[PrerequisiteRecord::RecordEquals {
                    name: owner.clone(),
                    rtype,
                    rdata: rdata.clone()
                }],
                &[UpdateRecord::DeleteRecord {
                    name: owner.clone(),
                    rtype,
                    rdata
                }],
                Some(&key)
            )
            .unwrap(),
            Rcode::NOERROR
        );
        assert!(
            !exported_record_sets(&app, zone)
                .await
                .contains_key(&(export_owner, rtype))
        );
    }
}
