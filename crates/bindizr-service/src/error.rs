use std::fmt;

use bindizr_core::{
    dns::{Serial, dnssec::KeyTag},
    model::{record::RecordId, role_grant::RoleGrantId},
};
use thiserror::Error;

/// Machine-readable error codes exposed to API and CLI clients. The
/// SCREAMING_SNAKE_CASE wire name is the public contract; what status a
/// code answers with is each transport's own table.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidInput,
    InvalidZoneField,
    InvalidRecordName,
    InvalidRecordValue,
    InvalidJsonBody,
    ZoneConflict,
    RecordConflict,
    TokenConflict,
    EndpointNotFound,
    MethodNotAllowed,
    ZoneNotFound,
    RecordNotFound,
    TokenNotFound,
    VersionNotFound,
    SecondaryNotFound,
    SecondaryConflict,
    TsigKeyNotFound,
    TsigKeyConflict,
    TsigKeyInUse,
    RoleNotFound,
    RoleConflict,
    RoleInUse,
    RoleGrantNotFound,
    DnssecAlreadyEnabled,
    DnssecNotEnabled,
    DnssecRolloverInProgress,
    DnssecNoRolloverInProgress,
    DnssecDsPublished,
    DnssecDsNotPublished,
    DnssecDsUnverified,
    DnssecPolicyNotFound,
    DnssecPolicyConflict,
    DnssecPolicyInUse,
    DnssecSigningFailed,
    Unauthorized,
    InvalidToken,
    Forbidden,
    PayloadTooLarge,
    UnsupportedMediaType,
    Internal,
}

impl ErrorCode {
    /// Return the text representation of this error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InvalidInput => "INVALID_INPUT",
            ErrorCode::InvalidZoneField => "INVALID_ZONE_FIELD",
            ErrorCode::InvalidRecordName => "INVALID_RECORD_NAME",
            ErrorCode::InvalidRecordValue => "INVALID_RECORD_VALUE",
            ErrorCode::InvalidJsonBody => "INVALID_JSON_BODY",
            ErrorCode::ZoneConflict => "ZONE_CONFLICT",
            ErrorCode::RecordConflict => "RECORD_CONFLICT",
            ErrorCode::TokenConflict => "TOKEN_CONFLICT",
            ErrorCode::EndpointNotFound => "ENDPOINT_NOT_FOUND",
            ErrorCode::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            ErrorCode::ZoneNotFound => "ZONE_NOT_FOUND",
            ErrorCode::RecordNotFound => "RECORD_NOT_FOUND",
            ErrorCode::TokenNotFound => "TOKEN_NOT_FOUND",
            ErrorCode::VersionNotFound => "VERSION_NOT_FOUND",
            ErrorCode::SecondaryNotFound => "SECONDARY_NOT_FOUND",
            ErrorCode::SecondaryConflict => "SECONDARY_CONFLICT",
            ErrorCode::TsigKeyNotFound => "TSIG_KEY_NOT_FOUND",
            ErrorCode::TsigKeyConflict => "TSIG_KEY_CONFLICT",
            ErrorCode::TsigKeyInUse => "TSIG_KEY_IN_USE",
            ErrorCode::RoleNotFound => "ROLE_NOT_FOUND",
            ErrorCode::RoleConflict => "ROLE_CONFLICT",
            ErrorCode::RoleInUse => "ROLE_IN_USE",
            ErrorCode::RoleGrantNotFound => "ROLE_GRANT_NOT_FOUND",
            ErrorCode::DnssecAlreadyEnabled => "DNSSEC_ALREADY_ENABLED",
            ErrorCode::DnssecNotEnabled => "DNSSEC_NOT_ENABLED",
            ErrorCode::DnssecRolloverInProgress => "DNSSEC_ROLLOVER_IN_PROGRESS",
            ErrorCode::DnssecNoRolloverInProgress => "DNSSEC_NO_ROLLOVER_IN_PROGRESS",
            ErrorCode::DnssecDsPublished => "DNSSEC_DS_PUBLISHED",
            ErrorCode::DnssecDsNotPublished => "DNSSEC_DS_NOT_PUBLISHED",
            ErrorCode::DnssecDsUnverified => "DNSSEC_DS_UNVERIFIED",
            ErrorCode::DnssecPolicyNotFound => "DNSSEC_POLICY_NOT_FOUND",
            ErrorCode::DnssecPolicyConflict => "DNSSEC_POLICY_CONFLICT",
            ErrorCode::DnssecPolicyInUse => "DNSSEC_POLICY_IN_USE",
            ErrorCode::DnssecSigningFailed => "DNSSEC_SIGNING_FAILED",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::InvalidToken => "INVALID_TOKEN",
            ErrorCode::Forbidden => "FORBIDDEN",
            ErrorCode::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            ErrorCode::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// Whether the failure is the server's, not the requester's: what a
    /// transport reports as a server fault (SERVFAIL, 500) rather than a
    /// refusal.
    pub fn is_internal(&self) -> bool {
        matches!(self, ErrorCode::DnssecSigningFailed | ErrorCode::Internal)
    }
}

/// Service failure with one variant per [`ErrorCode`] and a user-facing message.
/// Each transport maps the code to its own HTTP status, RCODE, or exit code.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    InvalidZoneField(String),
    #[error("{0}")]
    InvalidRecordName(String),
    #[error("{0}")]
    InvalidRecordValue(String),
    #[error("{0}")]
    InvalidJsonBody(String),
    #[error("{0}")]
    ZoneConflict(String),
    #[error("{0}")]
    RecordConflict(String),
    #[error("{0}")]
    TokenConflict(String),
    #[error("{0}")]
    EndpointNotFound(String),
    #[error("{0}")]
    MethodNotAllowed(String),
    #[error("{0}")]
    ZoneNotFound(String),
    #[error("{0}")]
    RecordNotFound(String),
    #[error("{0}")]
    TokenNotFound(String),
    #[error("{0}")]
    VersionNotFound(String),
    #[error("{0}")]
    SecondaryNotFound(String),
    #[error("{0}")]
    SecondaryConflict(String),
    #[error("{0}")]
    TsigKeyNotFound(String),
    #[error("{0}")]
    TsigKeyConflict(String),
    #[error("{0}")]
    TsigKeyInUse(String),
    #[error("{0}")]
    RoleNotFound(String),
    #[error("{0}")]
    RoleConflict(String),
    #[error("{0}")]
    RoleInUse(String),
    #[error("{0}")]
    RoleGrantNotFound(String),
    #[error("{0}")]
    DnssecAlreadyEnabled(String),
    #[error("{0}")]
    DnssecNotEnabled(String),
    #[error("{0}")]
    DnssecRolloverInProgress(String),
    #[error("{0}")]
    DnssecNoRolloverInProgress(String),
    #[error("{0}")]
    DnssecDsPublished(String),
    #[error("{0}")]
    DnssecDsNotPublished(String),
    #[error("{0}")]
    DnssecDsUnverified(String),
    #[error("{0}")]
    DnssecPolicyNotFound(String),
    #[error("{0}")]
    DnssecPolicyConflict(String),
    #[error("{0}")]
    DnssecPolicyInUse(String),
    /// A server fault named for alerting; the signer's error is its source.
    #[error("DNSSEC signing failed: {source}")]
    DnssecSigningFailed {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    InvalidToken(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("{0}")]
    UnsupportedMediaType(String),
    /// A server fault; the failure beneath it, when one was typed, is its
    /// source so a log can follow the chain.
    #[error("{message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

impl ServiceError {
    /// The machine-readable code of this error, the wire's classification.
    pub fn code(&self) -> ErrorCode {
        match self {
            ServiceError::InvalidInput(_) => ErrorCode::InvalidInput,
            ServiceError::InvalidZoneField(_) => ErrorCode::InvalidZoneField,
            ServiceError::InvalidRecordName(_) => ErrorCode::InvalidRecordName,
            ServiceError::InvalidRecordValue(_) => ErrorCode::InvalidRecordValue,
            ServiceError::InvalidJsonBody(_) => ErrorCode::InvalidJsonBody,
            ServiceError::ZoneConflict(_) => ErrorCode::ZoneConflict,
            ServiceError::RecordConflict(_) => ErrorCode::RecordConflict,
            ServiceError::TokenConflict(_) => ErrorCode::TokenConflict,
            ServiceError::EndpointNotFound(_) => ErrorCode::EndpointNotFound,
            ServiceError::MethodNotAllowed(_) => ErrorCode::MethodNotAllowed,
            ServiceError::ZoneNotFound(_) => ErrorCode::ZoneNotFound,
            ServiceError::RecordNotFound(_) => ErrorCode::RecordNotFound,
            ServiceError::TokenNotFound(_) => ErrorCode::TokenNotFound,
            ServiceError::VersionNotFound(_) => ErrorCode::VersionNotFound,
            ServiceError::SecondaryNotFound(_) => ErrorCode::SecondaryNotFound,
            ServiceError::SecondaryConflict(_) => ErrorCode::SecondaryConflict,
            ServiceError::TsigKeyNotFound(_) => ErrorCode::TsigKeyNotFound,
            ServiceError::TsigKeyConflict(_) => ErrorCode::TsigKeyConflict,
            ServiceError::TsigKeyInUse(_) => ErrorCode::TsigKeyInUse,
            ServiceError::RoleNotFound(_) => ErrorCode::RoleNotFound,
            ServiceError::RoleConflict(_) => ErrorCode::RoleConflict,
            ServiceError::RoleInUse(_) => ErrorCode::RoleInUse,
            ServiceError::RoleGrantNotFound(_) => ErrorCode::RoleGrantNotFound,
            ServiceError::DnssecAlreadyEnabled(_) => ErrorCode::DnssecAlreadyEnabled,
            ServiceError::DnssecNotEnabled(_) => ErrorCode::DnssecNotEnabled,
            ServiceError::DnssecRolloverInProgress(_) => ErrorCode::DnssecRolloverInProgress,
            ServiceError::DnssecNoRolloverInProgress(_) => ErrorCode::DnssecNoRolloverInProgress,
            ServiceError::DnssecDsPublished(_) => ErrorCode::DnssecDsPublished,
            ServiceError::DnssecDsNotPublished(_) => ErrorCode::DnssecDsNotPublished,
            ServiceError::DnssecDsUnverified(_) => ErrorCode::DnssecDsUnverified,
            ServiceError::DnssecPolicyNotFound(_) => ErrorCode::DnssecPolicyNotFound,
            ServiceError::DnssecPolicyConflict(_) => ErrorCode::DnssecPolicyConflict,
            ServiceError::DnssecPolicyInUse(_) => ErrorCode::DnssecPolicyInUse,
            ServiceError::DnssecSigningFailed { .. } => ErrorCode::DnssecSigningFailed,
            ServiceError::Unauthorized(_) => ErrorCode::Unauthorized,
            ServiceError::InvalidToken(_) => ErrorCode::InvalidToken,
            ServiceError::Forbidden(_) => ErrorCode::Forbidden,
            ServiceError::PayloadTooLarge(_) => ErrorCode::PayloadTooLarge,
            ServiceError::UnsupportedMediaType(_) => ErrorCode::UnsupportedMediaType,
            ServiceError::Internal { .. } => ErrorCode::Internal,
        }
    }
}

/// A database failure the service did not classify is internal; the sites
/// that read a UNIQUE or FK violation as a conflict do so where they call.
/// A stored serial that does not convert is corrupt data: a server fault.
impl From<bindizr_core::dns::ConvertSerialError> for ServiceError {
    /// Report the conversion failure as an internal error, keeping it as source.
    fn from(err: bindizr_core::dns::ConvertSerialError) -> Self {
        ServiceError::Internal {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// A stored TTL that does not convert is corrupt data: a server fault.
impl From<bindizr_core::dns::ConvertTtlError> for ServiceError {
    /// Report the conversion failure as an internal error, keeping it as source.
    fn from(err: bindizr_core::dns::ConvertTtlError) -> Self {
        ServiceError::Internal {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<bindizr_db::error::DatabaseError> for ServiceError {
    /// Wrap a database error as an internal service error.
    fn from(err: bindizr_db::error::DatabaseError) -> Self {
        ServiceError::Internal {
            message: format!("database error: {}", err),
            source: Some(Box::new(err)),
        }
    }
}

impl ServiceError {
    /// Build an error for invalid request input.
    pub fn invalid_input(message: impl fmt::Display) -> Self {
        ServiceError::InvalidInput(message.to_string())
    }

    /// Build an error for an invalid zone field.
    pub fn invalid_zone_field(message: impl fmt::Display) -> Self {
        ServiceError::InvalidZoneField(message.to_string())
    }

    /// Build an error for an invalid record owner name.
    pub fn invalid_record_name(message: impl fmt::Display) -> Self {
        ServiceError::InvalidRecordName(message.to_string())
    }

    /// Build an error for an invalid record value.
    pub fn invalid_record_value(message: impl fmt::Display) -> Self {
        ServiceError::InvalidRecordValue(message.to_string())
    }

    /// Build an error for a conflicting zone mutation.
    pub fn zone_conflict(message: impl fmt::Display) -> Self {
        ServiceError::ZoneConflict(message.to_string())
    }

    /// Build an error for a conflicting record mutation.
    pub fn record_conflict(message: impl fmt::Display) -> Self {
        ServiceError::RecordConflict(message.to_string())
    }

    /// Build an error for a request without valid authentication.
    pub fn unauthorized(message: impl fmt::Display) -> Self {
        ServiceError::Unauthorized(message.to_string())
    }

    /// Build an error for an invalid API token.
    pub fn invalid_token(message: impl fmt::Display) -> Self {
        ServiceError::InvalidToken(message.to_string())
    }

    /// Build an error for an operation the caller may not perform.
    pub fn forbidden(message: impl fmt::Display) -> Self {
        ServiceError::Forbidden(message.to_string())
    }

    /// Build an error for an internal service failure.
    pub fn internal(message: impl fmt::Display) -> Self {
        ServiceError::Internal {
            message: message.to_string(),
            source: None,
        }
    }

    /// Keep an internal failure as the source of an operation-specific message.
    pub fn internal_with_source(
        message: impl fmt::Display,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ServiceError::Internal {
            message: message.to_string(),
            source: Some(Box::new(source)),
        }
    }

    /// Build an error naming the missing zone.
    pub fn zone_not_found(name: impl fmt::Display) -> Self {
        ServiceError::ZoneNotFound(format!("zone with name '{}' not found", name))
    }

    /// Build an error identifying the missing record.
    pub fn record_not_found(id: RecordId) -> Self {
        ServiceError::RecordNotFound(format!("record with id '{}' not found", id))
    }

    /// Build an error identifying the owner name that holds no record.
    pub fn record_not_found_at_name(
        zone_name: impl std::fmt::Display,
        name: impl std::fmt::Display,
    ) -> Self {
        ServiceError::RecordNotFound(format!(
            "no record named '{}' in zone '{}'",
            name, zone_name
        ))
    }

    /// Report an ambiguous owner name, asking for a record id in transport-neutral terms.
    pub fn record_name_ambiguous(
        zone_name: impl std::fmt::Display,
        name: impl std::fmt::Display,
        matched: usize,
    ) -> Self {
        ServiceError::InvalidInput(format!(
            "{} records are named '{}' in zone '{}'; address one by its id",
            matched, name, zone_name
        ))
    }

    /// Build an error naming the missing API token.
    pub fn token_not_found(name: impl fmt::Display) -> Self {
        ServiceError::TokenNotFound(format!("API token with name '{}' not found", name))
    }

    /// Build an error for an API token name already in use.
    pub fn token_conflict(name: impl fmt::Display) -> Self {
        ServiceError::TokenConflict(format!("API token with name '{}' already exists", name))
    }

    /// Build an error naming the missing secondary.
    pub fn secondary_not_found(name: impl fmt::Display) -> Self {
        ServiceError::SecondaryNotFound(format!("secondary with name '{}' not found", name))
    }

    /// Build an error for a secondary name or address already in use.
    pub fn secondary_conflict(message: impl fmt::Display) -> Self {
        ServiceError::SecondaryConflict(message.to_string())
    }

    /// Build an error naming the missing TSIG key.
    pub fn tsig_key_not_found(name: impl fmt::Display) -> Self {
        ServiceError::TsigKeyNotFound(format!("TSIG key with name '{}' not found", name))
    }

    /// Build an error for a TSIG key name already in use.
    pub fn tsig_key_conflict(name: impl fmt::Display) -> Self {
        ServiceError::TsigKeyConflict(format!("TSIG key with name '{}' already exists", name))
    }

    /// Build an error naming the missing role.
    pub fn role_not_found(name: impl fmt::Display) -> Self {
        ServiceError::RoleNotFound(format!("role with name '{}' not found", name))
    }

    /// Build an error for a role name already in use.
    pub fn role_conflict(name: impl fmt::Display) -> Self {
        ServiceError::RoleConflict(format!("role with name '{}' already exists", name))
    }

    /// Build an error explaining that credentials still authenticate into a role.
    pub fn role_in_use(name: impl fmt::Display, tokens: u64, keys: u64) -> Self {
        ServiceError::RoleInUse(format!(
            "role '{}' is still held by {} API token{} and {} TSIG key{}",
            name,
            tokens,
            if tokens == 1 { "" } else { "s" },
            keys,
            if keys == 1 { "" } else { "s" }
        ))
    }

    /// Build an error identifying the missing role grant.
    pub fn role_grant_not_found(id: RoleGrantId) -> Self {
        ServiceError::RoleGrantNotFound(format!("role grant with id '{}' not found", id))
    }

    /// Build an error for enabling DNSSEC on an already signed zone.
    pub fn dnssec_already_enabled(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecAlreadyEnabled(format!(
            "DNSSEC is already enabled for zone '{}'",
            zone_name
        ))
    }

    /// Build an error for an operation requiring DNSSEC on an unsigned zone.
    pub fn dnssec_not_enabled(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecNotEnabled(format!("DNSSEC is not enabled for zone '{}'", zone_name))
    }

    /// Build an error from what the signer could not do.
    pub fn dnssec_signing_failed(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        ServiceError::DnssecSigningFailed {
            source: Box::new(source),
        }
    }

    /// Build an error for a rollover already in progress.
    pub fn dnssec_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecRolloverInProgress(format!(
            "a key rollover is already in progress for zone '{}'",
            zone_name
        ))
    }

    /// Build an error for confirming a rollover that has not started.
    pub fn dnssec_no_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecNoRolloverInProgress(format!(
            "no key rollover is in progress for zone '{}'",
            zone_name
        ))
    }

    /// Build an error listing DS records that still block DNSSEC removal.
    pub fn dnssec_ds_published(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        ServiceError::DnssecDsPublished(format!(
            "the parent zone still serves DS records for zone '{}' (key tag{} {}); remove \
                 them and wait out their TTL before disabling DNSSEC, or skip the DS check",
            zone_name,
            if key_tags.len() == 1 { "" } else { "s" },
            key_tags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    /// Build an error listing DS records still required for key promotion.
    pub fn dnssec_ds_not_published(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        ServiceError::DnssecDsNotPublished(format!(
            "the parent zone serves no DS yet for key tag{} {} of zone '{}'; register it \
                 and wait out the DS TTL before confirming, or skip the DS check",
            if key_tags.len() == 1 { "" } else { "s" },
            key_tags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            zone_name
        ))
    }

    /// Build an error for parent DS digests that cannot be verified.
    pub fn dnssec_ds_digest_unsupported(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        ServiceError::DnssecDsUnverified(format!(
            "the parent zone serves a DS for key tag{} {} of zone '{}', but only in digest \
                 types bindizr cannot compute, so the match cannot be confirmed; ask the parent \
                 to publish SHA-256, or skip the DS check",
            if key_tags.len() == 1 { "" } else { "s" },
            key_tags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            zone_name
        ))
    }

    /// Build an error explaining why the parent DS check could not finish.
    pub fn dnssec_ds_unverified(zone_name: impl fmt::Display, reason: impl fmt::Display) -> Self {
        ServiceError::DnssecDsUnverified(format!(
            "could not verify that the parent zone serves no DS for zone '{}': {}; set the \
                 zone's parent nameserver addresses, or skip the DS check",
            zone_name, reason
        ))
    }

    /// Build an error naming the missing DNSSEC policy.
    pub fn dnssec_policy_not_found(name: impl fmt::Display) -> Self {
        ServiceError::DnssecPolicyNotFound(format!("DNSSEC policy with name '{}' not found", name))
    }

    /// Build an error for a DNSSEC policy name already in use.
    pub fn dnssec_policy_conflict(name: impl fmt::Display) -> Self {
        ServiceError::DnssecPolicyConflict(format!(
            "DNSSEC policy with name '{}' already exists",
            name
        ))
    }

    /// Build an error explaining that zones still use a DNSSEC policy.
    pub fn dnssec_policy_in_use(name: impl fmt::Display, zone_count: u64) -> Self {
        ServiceError::DnssecPolicyInUse(format!(
            "DNSSEC policy '{}' is used by {} signed zone{}",
            name,
            zone_count,
            if zone_count == 1 { "" } else { "s" }
        ))
    }

    /// Build an error naming the missing zone serial.
    pub fn version_not_found(zone_name: impl fmt::Display, serial: Serial) -> Self {
        ServiceError::VersionNotFound(format!(
            "no version with serial '{}' for zone '{}'",
            serial, zone_name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a signing failure is not an internal error.
    #[test]
    fn a_signing_failure_is_not_an_internal_error() {
        let err = ServiceError::dnssec_signing_failed(std::io::Error::other("boom"));
        assert_eq!(err.code(), ErrorCode::DnssecSigningFailed);
        assert!(err.code().is_internal());
    }

    /// Preserve the concrete source when an internal failure gains context.
    #[test]
    fn internal_context_preserves_the_source() {
        use std::error::Error;
        let error = ServiceError::internal_with_source(
            "failed to load records",
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "database disconnected"),
        );
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(error.to_string(), "failed to load records");
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// Verify every serialized error code against its established wire spelling.
    #[test]
    fn error_code_spells_itself_once() {
        for (value, expected) in [
            (ErrorCode::InvalidInput, "INVALID_INPUT"),
            (ErrorCode::InvalidZoneField, "INVALID_ZONE_FIELD"),
            (ErrorCode::InvalidRecordName, "INVALID_RECORD_NAME"),
            (ErrorCode::InvalidRecordValue, "INVALID_RECORD_VALUE"),
            (ErrorCode::InvalidJsonBody, "INVALID_JSON_BODY"),
            (ErrorCode::ZoneConflict, "ZONE_CONFLICT"),
            (ErrorCode::RecordConflict, "RECORD_CONFLICT"),
            (ErrorCode::TokenConflict, "TOKEN_CONFLICT"),
            (ErrorCode::EndpointNotFound, "ENDPOINT_NOT_FOUND"),
            (ErrorCode::MethodNotAllowed, "METHOD_NOT_ALLOWED"),
            (ErrorCode::ZoneNotFound, "ZONE_NOT_FOUND"),
            (ErrorCode::RecordNotFound, "RECORD_NOT_FOUND"),
            (ErrorCode::TokenNotFound, "TOKEN_NOT_FOUND"),
            (ErrorCode::VersionNotFound, "VERSION_NOT_FOUND"),
            (ErrorCode::SecondaryNotFound, "SECONDARY_NOT_FOUND"),
            (ErrorCode::SecondaryConflict, "SECONDARY_CONFLICT"),
            (ErrorCode::TsigKeyNotFound, "TSIG_KEY_NOT_FOUND"),
            (ErrorCode::TsigKeyConflict, "TSIG_KEY_CONFLICT"),
            (ErrorCode::TsigKeyInUse, "TSIG_KEY_IN_USE"),
            (ErrorCode::RoleNotFound, "ROLE_NOT_FOUND"),
            (ErrorCode::RoleConflict, "ROLE_CONFLICT"),
            (ErrorCode::RoleInUse, "ROLE_IN_USE"),
            (ErrorCode::RoleGrantNotFound, "ROLE_GRANT_NOT_FOUND"),
            (ErrorCode::DnssecAlreadyEnabled, "DNSSEC_ALREADY_ENABLED"),
            (ErrorCode::DnssecNotEnabled, "DNSSEC_NOT_ENABLED"),
            (
                ErrorCode::DnssecRolloverInProgress,
                "DNSSEC_ROLLOVER_IN_PROGRESS",
            ),
            (
                ErrorCode::DnssecNoRolloverInProgress,
                "DNSSEC_NO_ROLLOVER_IN_PROGRESS",
            ),
            (ErrorCode::DnssecDsPublished, "DNSSEC_DS_PUBLISHED"),
            (ErrorCode::DnssecDsNotPublished, "DNSSEC_DS_NOT_PUBLISHED"),
            (ErrorCode::DnssecDsUnverified, "DNSSEC_DS_UNVERIFIED"),
            (ErrorCode::DnssecPolicyNotFound, "DNSSEC_POLICY_NOT_FOUND"),
            (ErrorCode::DnssecPolicyConflict, "DNSSEC_POLICY_CONFLICT"),
            (ErrorCode::DnssecPolicyInUse, "DNSSEC_POLICY_IN_USE"),
            (ErrorCode::DnssecSigningFailed, "DNSSEC_SIGNING_FAILED"),
            (ErrorCode::Unauthorized, "UNAUTHORIZED"),
            (ErrorCode::InvalidToken, "INVALID_TOKEN"),
            (ErrorCode::Forbidden, "FORBIDDEN"),
            (ErrorCode::PayloadTooLarge, "PAYLOAD_TOO_LARGE"),
            (ErrorCode::UnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE"),
            (ErrorCode::Internal, "INTERNAL"),
        ] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<ErrorCode>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }
}
