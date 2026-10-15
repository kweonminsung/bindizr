use std::error::Error;

use super::*;

/// Verify that owner in zone reduces an in zone owner to its stored form.
#[test]
fn parse_owner_in_zone_reduces_an_in_zone_owner_to_its_stored_form() {
    assert_eq!(
        parse_update_owner("www.example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .to_stored(),
        "www"
    );
    assert!(
        parse_update_owner("example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .is_apex()
    );
    // A dotted wire label is one label, so it is data rather than a boundary.
    assert_eq!(
        parse_update_owner(
            r"host\.name.example.com.",
            &ZoneName::from_row("example.com")
        )
        .unwrap()
        .labels(),
        [b"host.name".to_vec()]
    );
}

/// Verify that `parse_update_owner` rejects owners outside the zone.
#[test]
fn parse_owner_in_zone_rejects_owners_outside_the_zone() {
    for owner in [
        "aexample.com.",
        "badexample.com.",
        "www.badexample.com.",
        ".",
        // One label spelling the zone is not inside it.
        r"evil\.example.com.",
    ] {
        let err = parse_update_owner(owner, &ZoneName::from_row("example.com")).unwrap_err();
        assert_eq!(err.rcode(), Rcode::NOTZONE, "{owner:?}");
    }
}

/// Preserve parser failures while retaining their FORMERR classification.
#[test]
fn parser_errors_retain_their_sources() {
    let shape = ValidateUpdateShapeError::NonzeroTtl;
    let err = NsupdateError::from(shape);
    assert_eq!(err.rcode(), Rcode::FORMERR);
    assert_eq!(
        err.source()
            .unwrap()
            .downcast_ref::<ValidateUpdateShapeError>(),
        Some(&shape)
    );

    let parse = ParseUpdateError::Rdata {
        record_type: "A".to_string(),
    };
    let err = NsupdateError::from(parse.clone());
    assert_eq!(err.rcode(), Rcode::FORMERR);
    assert_eq!(
        err.source().unwrap().downcast_ref::<ParseUpdateError>(),
        Some(&parse)
    );
}

/// Keep caller and backend failures typed, with their original DNS classifications.
#[test]
fn service_errors_retain_their_sources_and_classification() {
    for (source, rcode) in [
        (
            ServiceError::forbidden("denied".to_string()),
            Rcode::REFUSED,
        ),
        (
            ServiceError::invalid_input("invalid".to_string()),
            Rcode::REFUSED,
        ),
        (
            ServiceError::internal_with_source("storage failed", std::io::Error::other("storage")),
            Rcode::SERVFAIL,
        ),
        (
            ServiceError::dnssec_signing_failed(std::io::Error::other("signer")),
            Rcode::SERVFAIL,
        ),
    ] {
        let message = source.to_string();
        let err = NsupdateError::from(source);
        assert_eq!(err.rcode(), rcode);
        assert_eq!(err.to_string(), message);
        let service = err
            .source()
            .unwrap()
            .downcast_ref::<ServiceError>()
            .unwrap();
        if rcode == Rcode::SERVFAIL {
            assert!(service.source().unwrap().is::<std::io::Error>());
        }
    }
}

/// Distinguish an outside-zone owner from malformed names without losing the parser cause.
#[test]
fn owner_errors_retain_their_sources_and_classification() {
    let zone = ZoneName::parse("example.com").unwrap();
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
        let err = parse_update_owner(name, &zone).unwrap_err();
        assert_eq!(err.rcode(), rcode);
        assert_eq!(
            err.source().unwrap().downcast_ref::<ParseNameError>(),
            Some(&source)
        );
    }
}
