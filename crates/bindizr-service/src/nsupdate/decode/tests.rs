use std::error::Error;
use std::slice;

use bindizr_core::dns::message::Rcode;
use bindizr_core::dns::name::ParseNameError;

use super::*;

/// Build a wire record whose RDATA starts at the beginning of its test message.
fn record(class: Class, rtype: Rtype, ttl: u32, rdata: &[u8]) -> UpdateRecord {
    UpdateRecord {
        name: "host.example.com.".to_string(),
        record_type: rtype,
        class,
        ttl,
        rdata: rdata.to_vec(),
        rdata_start: 0,
    }
}

/// Verify that managed changes return REFUSED and malformed RDATA returns FORMERR.
#[test]
fn nsupdate_decode_rejects_managed_dnssec_changes_after_validating_wire_data() {
    let zone_name = ZoneName::parse("example.com").unwrap();

    for class in [Class::IN, Class::NONE, Class::ANY] {
        let data = if class == Class::ANY {
            &[][..]
        } else {
            &[1, 1, 3, 13, 1][..]
        };
        let error =
            decode_updates(&[record(class, Rtype::DNSKEY, 0, data)], &zone_name, data).unwrap_err();

        assert!(matches!(error, NsupdateError::ManagedType(Rtype::DNSKEY)));
        assert_eq!(error.rcode().ok(), Some(Rcode::REFUSED));
    }

    for class in [Class::IN, Class::NONE] {
        let error =
            decode_updates(&[record(class, Rtype::DNSKEY, 0, &[1])], &zone_name, &[1]).unwrap_err();
        assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR));
    }

    let value = [1, 1, 3, 13, 1];

    for class in [Class::IN, Class::ANY, Class::NONE] {
        let data = if class == Class::IN {
            &value[..]
        } else {
            &[][..]
        };
        assert!(
            decode_prerequisite(&record(class, Rtype::DNSKEY, 0, data), &zone_name, data).is_ok()
        );
    }

    assert!(matches!(
        &decode_updates(&[record(Class::ANY, Rtype::ANY, 0, &[])], &zone_name, &[]).unwrap()[0],
        UpdateOperation::Record(RecordOperation::DeleteRecordSet {
            record_type: None,
            ..
        })
    ));
}

/// Verify that malformed prerequisite and update shapes are reported as FORMERR
/// (RFC 2136, Sections 3.2.1 and 3.4.1).
#[test]
fn nsupdate_decode_returns_formerr_for_malformed_sections() {
    let zone_name = ZoneName::parse("example.com").unwrap();

    for prerequisite in [
        record(Class::ANY, Rtype::ANY, 1, &[]),
        record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
        record(Class::IN, Rtype::ANY, 0, &[]),
        record(Class::CH, Rtype::ANY, 0, &[]),
    ] {
        let error = decode_prerequisite(&prerequisite, &zone_name, &[]).unwrap_err();
        assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR), "{error}");
    }

    for update in [
        record(Class::NONE, Rtype::ANY, 0, &[]),
        record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
        record(Class::IN, Rtype::AXFR, 0, &[]),
        record(Class::CH, Rtype::A, 0, &[1, 2, 3, 4]),
    ] {
        let error = decode_updates(&[update], &zone_name, &[]).unwrap_err();
        assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR), "{error}");
    }
}

/// Verify that ineffective deletes still pass every prescan check, including
/// names whose escaped dots cannot act as zone boundaries (RFC 2136, Section 3.4.1).
#[test]
fn nsupdate_decode_validates_ignored_delete_owners_and_shapes() {
    let zone_name = ZoneName::parse("example.com").unwrap();

    for (rtype, data) in [
        (Rtype::SOA, vec![0; 22]),
        (Rtype::HINFO, vec![0; 2]),
        (Rtype::from_int(65280), vec![1]),
    ] {
        for class in [Class::ANY, Class::NONE] {
            let data = if class == Class::ANY {
                &[][..]
            } else {
                &data
            };
            let valid = record(class, rtype, 0, data);
            let result = decode_updates(slice::from_ref(&valid), &zone_name, data);

            if rtype == Rtype::SOA {
                assert!(result.unwrap().is_empty());
            } else {
                // RFC 2136, Section 3.4.1.2: an unrecognized type fails the prescan.
                assert_eq!(result.unwrap_err().rcode().ok(), Some(Rcode::FORMERR));
            }

            for name in ["elsewhere.example.net.", r"outside\.example.com.", "."] {
                let mut outside = valid.clone();
                outside.name = name.to_string();
                let error = decode_updates(&[outside], &zone_name, data).unwrap_err();
                assert_eq!(error.rcode().ok(), Some(Rcode::NOTZONE), "{error}");
            }

            let mut malformed = valid;
            malformed.ttl = 1;
            let error = decode_updates(&[malformed], &zone_name, data).unwrap_err();

            assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR), "{error}");
        }
    }
}

/// Verify that every record is prescanned before RDATA is decoded or an
/// ineffective delete is omitted (RFC 2136, Section 3.4.1).
#[test]
fn nsupdate_decode_prescans_all_records_before_decoding_operations() {
    let zone_name = ZoneName::parse("example.com").unwrap();
    let malformed_add = record(Class::IN, Rtype::A, 0, &[]);
    let mut outside = record(Class::ANY, Rtype::SOA, 0, &[]);
    outside.name = "outside.example.net.".to_string();
    let error = decode_updates(&[malformed_add, outside], &zone_name, &[]).unwrap_err();
    assert_eq!(error.rcode().ok(), Some(Rcode::NOTZONE), "{error}");
}

/// Verify that execution receives the checked owner, and an add with a
/// high-bit TTL retains its unsigned value (RFC 8767, Section 4).
#[test]
fn nsupdate_decode_returns_operations_with_checked_owners() {
    let zone_name = ZoneName::parse("example.com").unwrap();
    let message = [192, 0, 2, 1];
    let mut add = record(Class::IN, Rtype::A, u32::MAX, &message);
    add.name = r"host\.name.example.com.".to_string();
    let operations = decode_updates(&[add], &zone_name, &message).unwrap();

    match &operations[0] {
        UpdateOperation::Record(RecordOperation::AddRecord {
            name: owner, ttl, ..
        }) => {
            assert_eq!(owner.labels(), [b"host.name".to_vec()]);
            assert_eq!(ttl.as_secs(), u32::MAX);
        }
        other => panic!("{other:?}"),
    }
}

/// Verify that `parse_update_owner` reduces an in-zone owner to its stored form.
#[test]
fn parse_update_owner_reduces_an_in_zone_owner_to_its_stored_form() {
    assert_eq!(
        parse_update_owner("www.example.com.", &ZoneName::parse("example.com").unwrap())
            .unwrap()
            .to_stored(),
        "www"
    );
    assert!(
        parse_update_owner("example.com.", &ZoneName::parse("example.com").unwrap())
            .unwrap()
            .is_apex()
    );

    // A dotted wire label is one label, so it is data rather than a boundary.
    assert_eq!(
        parse_update_owner(
            r"host\.name.example.com.",
            &ZoneName::parse("example.com").unwrap()
        )
        .unwrap()
        .labels(),
        [b"host.name".to_vec()]
    );
}

/// Verify that `parse_update_owner` rejects owners outside the zone.
#[test]
fn parse_update_owner_rejects_owners_outside_the_zone() {
    for owner in [
        "aexample.com.",
        "badexample.com.",
        "www.badexample.com.",
        ".",
        // One label spelling the zone is not inside it.
        r"evil\.example.com.",
    ] {
        let error =
            parse_update_owner(owner, &ZoneName::parse("example.com").unwrap()).unwrap_err();
        assert_eq!(error.rcode().ok(), Some(Rcode::NOTZONE), "{owner:?}");
    }
}

/// Verify that an outside-zone owner is distinguished from malformed names without losing the
/// parser cause.
#[test]
fn owner_errors_retain_their_sources_and_classification() {
    let zone_name = ZoneName::parse("example.com").unwrap();

    for (name, source, rcode) in [
        (
            "outside.example.net.",
            ParseNameError::OutsideZone,
            Rcode::NOTZONE,
        ),
        (
            "bad..example.com.",
            ParseNameError::EmptyLabel,
            Rcode::REFUSED,
        ),
    ] {
        let error = parse_update_owner(name, &zone_name).unwrap_err();
        assert_eq!(error.rcode().ok(), Some(rcode));
        assert_eq!(
            error.source().unwrap().downcast_ref::<ParseNameError>(),
            Some(&source)
        );
    }
}
