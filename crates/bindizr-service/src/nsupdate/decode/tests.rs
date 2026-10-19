use bindizr_core::dns::message::Rcode;

use super::*;

/// A wire record whose RDATA starts at the beginning of its test message.
fn record(class: Class, record_type: Rtype, ttl: u32, rdata: &[u8]) -> UpdateRecord {
    UpdateRecord {
        name: "host.example.com.".to_string(),
        record_type,
        class,
        ttl,
        rdata: rdata.to_vec(),
        rdata_start: 0,
    }
}

/// Managed changes return REFUSED; malformed RDATA returns FORMERR.
#[test]
fn nsupdate_decode_refuses_managed_dnssec_changes_after_validating_wire_data() {
    let zone = ZoneName::parse("example.com").unwrap();
    for class in [Class::IN, Class::NONE, Class::ANY] {
        let data = if class == Class::ANY {
            &[][..]
        } else {
            &[1, 1, 3, 13, 1][..]
        };
        let err =
            decode_updates(&[record(class, Rtype::DNSKEY, 0, data)], &zone, data).unwrap_err();
        assert!(matches!(err, NsupdateError::ManagedType(Rtype::DNSKEY)));
        assert_eq!(err.rcode(), Rcode::REFUSED);
    }
    for class in [Class::IN, Class::NONE] {
        let err =
            decode_updates(&[record(class, Rtype::DNSKEY, 0, &[1])], &zone, &[1]).unwrap_err();
        assert_eq!(err.rcode(), Rcode::FORMERR);
    }
    let value = [1, 1, 3, 13, 1];
    for class in [Class::IN, Class::ANY, Class::NONE] {
        let data = if class == Class::IN {
            &value[..]
        } else {
            &[][..]
        };
        assert!(
            decode_prerequisites(&[record(class, Rtype::DNSKEY, 0, data)], &zone, data).is_ok()
        );
    }
    assert!(matches!(
        &decode_updates(&[record(Class::ANY, Rtype::ANY, 0, &[])], &zone, &[]).unwrap()[0],
        UpdateOperation::Record(RecordOperation::DeleteRecordSet {
            record_type: None,
            ..
        })
    ));
}

/// Verify the prerequisite and update shapes are reported as FORMERR
/// (RFC 2136, Sections 3.2.1 and 3.4.1).
#[test]
fn nsupdate_decode_returns_formerr_for_malformed_sections() {
    let zone = ZoneName::parse("example.com").unwrap();
    for prerequisite in [
        record(Class::ANY, Rtype::ANY, 1, &[]),
        record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
        record(Class::IN, Rtype::ANY, 0, &[]),
        record(Class::CH, Rtype::ANY, 0, &[]),
    ] {
        let err = decode_prerequisites(&[prerequisite], &zone, &[]).unwrap_err();
        assert_eq!(err.rcode(), Rcode::FORMERR, "{err}");
    }
    for update in [
        record(Class::NONE, Rtype::ANY, 0, &[]),
        record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
        record(Class::IN, Rtype::AXFR, 0, &[]),
        record(Class::CH, Rtype::A, 0, &[1, 2, 3, 4]),
    ] {
        let err = decode_updates(&[update], &zone, &[]).unwrap_err();
        assert_eq!(err.rcode(), Rcode::FORMERR, "{err}");
    }
}

/// Verify that ineffective deletes still pass every prescan check, including
/// names whose escaped dots cannot act as zone boundaries (RFC 2136, Section 3.4.1).
#[test]
fn nsupdate_decode_validates_ignored_delete_owners_and_shapes() {
    let zone = ZoneName::parse("example.com").unwrap();
    for (rtype, data) in [
        (Rtype::SOA, vec![0; 22]),
        (Rtype::HINFO, vec![0; 2]),
        (Rtype::from_int(65280), vec![1]),
    ] {
        for class in [Class::ANY, Class::NONE] {
            let data = if class == Class::ANY { &[][..] } else { &data };
            let valid = record(class, rtype, 0, data);
            let result = decode_updates(std::slice::from_ref(&valid), &zone, data);
            if rtype == Rtype::SOA {
                assert!(result.unwrap().is_empty());
            } else {
                assert_eq!(result.unwrap_err().rcode(), Rcode::REFUSED);
            }
            for name in ["elsewhere.example.net.", r"outside\.example.com.", "."] {
                let mut outside = valid.clone();
                outside.name = name.to_string();
                let err = decode_updates(&[outside], &zone, data).unwrap_err();
                assert_eq!(err.rcode(), Rcode::NOTZONE, "{err}");
            }
            let mut malformed = valid;
            malformed.ttl = 1;
            let err = decode_updates(&[malformed], &zone, data).unwrap_err();
            assert_eq!(err.rcode(), Rcode::FORMERR, "{err}");
        }
    }
}

/// Verify that every record is prescanned before RDATA is decoded or an
/// ineffective delete is omitted (RFC 2136, Section 3.4.1).
#[test]
fn nsupdate_decode_prescans_all_records_before_decoding_operations() {
    let zone = ZoneName::parse("example.com").unwrap();
    let malformed_add = record(Class::IN, Rtype::A, 0, &[]);
    let mut outside = record(Class::ANY, Rtype::SOA, 0, &[]);
    outside.name = "outside.example.net.".to_string();
    let err = decode_updates(&[malformed_add, outside], &zone, &[]).unwrap_err();
    assert_eq!(err.rcode(), Rcode::NOTZONE, "{err}");
}

/// Verify that execution receives the checked owner, and an add with a
/// high-bit TTL retains its unsigned value (RFC 8767, Section 4).
#[test]
fn nsupdate_decode_returns_operations_with_checked_owners() {
    let zone = ZoneName::parse("example.com").unwrap();
    let message = [192, 0, 2, 1];
    let mut add = record(Class::IN, Rtype::A, u32::MAX, &message);
    add.name = r"host\.name.example.com.".to_string();
    let operations = decode_updates(&[add], &zone, &message).unwrap();
    match &operations[0] {
        UpdateOperation::Record(RecordOperation::AddRecord { name, ttl, .. }) => {
            assert_eq!(name.labels(), [b"host.name".to_vec()]);
            assert_eq!(ttl.as_secs(), u32::MAX);
        }
        other => panic!("{other:?}"),
    }
}
