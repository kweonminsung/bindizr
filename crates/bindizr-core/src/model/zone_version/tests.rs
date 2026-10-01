use serde_json::json;

use super::*;

/// The scalar columns and API object preserve the same actor kind and name.
#[test]
fn actor_columns_match_the_api_identity() {
    for actor in [
        ChangeActor::Token {
            name: "admin".into(),
        },
        ChangeActor::TsigKey {
            name: "admin".into(),
        },
    ] {
        let (kind, name) = actor.as_columns();
        assert_eq!(
            serde_json::to_value(&actor).unwrap(),
            json!({ "kind": kind, "name": name })
        );
        let decoded = Option::<ChangeActor>::try_from(ChangeActorColumns {
            changed_by_kind: Some(kind.into()),
            changed_by_name: Some(name.into()),
        })
        .unwrap();
        assert_eq!(decoded, Some(actor));
    }
}

/// Corrupt column pairs fail decoding instead of dropping or inventing an identity.
#[test]
fn actor_columns_decode_only_complete_known_identities() {
    assert_eq!(
        Option::<ChangeActor>::try_from(ChangeActorColumns {
            changed_by_kind: None,
            changed_by_name: None,
        })
        .unwrap(),
        None
    );
    for (kind, name, expected) in [
        (Some("token"), None, DecodeChangeActorError::Incomplete),
        (None, Some("admin"), DecodeChangeActorError::Incomplete),
        (
            Some("unknown"),
            Some("admin"),
            DecodeChangeActorError::UnknownKind {
                value: "unknown".into(),
            },
        ),
    ] {
        let err = Option::<ChangeActor>::try_from(ChangeActorColumns {
            changed_by_kind: kind.map(str::to_string),
            changed_by_name: name.map(str::to_string),
        })
        .unwrap_err();
        assert_eq!(err, expected);
    }
}

/// Verify that `ChangeSource` has one spelling across `as_str`, serde, and `FromStr`.
#[test]
fn change_source_spells_itself_once() {
    for value in [
        ChangeSource::Api,
        ChangeSource::Socket,
        ChangeSource::Nsupdate,
        ChangeSource::System,
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
        assert_eq!(
            serde_json::from_value::<ChangeSource>(json!(value.as_str())).unwrap(),
            value
        );
        assert_eq!(value.as_str().parse::<ChangeSource>().unwrap(), value);
    }
}
/// Verify the canonical spelling and round-trip of every VersionFilter variant.
#[test]
fn version_filter_spells_itself_once() {
    for (value, expected) in [
        (
            VersionFilter::ExcludePastSignerOnly,
            "exclude_past_signer_only",
        ),
        (VersionFilter::All, "all"),
    ] {
        assert_eq!(value.as_str(), expected);
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::json!(expected)
        );
        assert_eq!(
            serde_json::from_value::<VersionFilter>(serde_json::json!(expected)).unwrap(),
            value
        );
    }
}
