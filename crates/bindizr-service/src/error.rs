use std::fmt;

use bindizr_core::{
    dns::{Serial, dnssec::KeyTag},
    model::{record::RecordId, token_grant::TokenGrantId, tsig_grant::TsigGrantId},
};
use thiserror::Error;

/// Machine-readable error codes exposed to API and CLI clients. The
/// SCREAMING_SNAKE_CASE wire name is the public contract; what status a
/// code answers with is each transport's own table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    TsigGrantNotFound,
    TokenGrantNotFound,
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
            ErrorCode::TsigGrantNotFound => "TSIG_GRANT_NOT_FOUND",
            ErrorCode::TokenGrantNotFound => "TOKEN_GRANT_NOT_FOUND",
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

    /// Inverse of [`ErrorCode::as_str`]; unknown names return `None` so
    /// clients degrade gracefully.
    pub fn parse(s: &str) -> Option<ErrorCode> {
        Some(match s {
            "INVALID_INPUT" => ErrorCode::InvalidInput,
            "INVALID_ZONE_FIELD" => ErrorCode::InvalidZoneField,
            "INVALID_RECORD_NAME" => ErrorCode::InvalidRecordName,
            "INVALID_RECORD_VALUE" => ErrorCode::InvalidRecordValue,
            "INVALID_JSON_BODY" => ErrorCode::InvalidJsonBody,
            "ZONE_CONFLICT" => ErrorCode::ZoneConflict,
            "RECORD_CONFLICT" => ErrorCode::RecordConflict,
            "TOKEN_CONFLICT" => ErrorCode::TokenConflict,
            "ENDPOINT_NOT_FOUND" => ErrorCode::EndpointNotFound,
            "METHOD_NOT_ALLOWED" => ErrorCode::MethodNotAllowed,
            "ZONE_NOT_FOUND" => ErrorCode::ZoneNotFound,
            "RECORD_NOT_FOUND" => ErrorCode::RecordNotFound,
            "TOKEN_NOT_FOUND" => ErrorCode::TokenNotFound,
            "VERSION_NOT_FOUND" => ErrorCode::VersionNotFound,
            "SECONDARY_NOT_FOUND" => ErrorCode::SecondaryNotFound,
            "SECONDARY_CONFLICT" => ErrorCode::SecondaryConflict,
            "TSIG_KEY_NOT_FOUND" => ErrorCode::TsigKeyNotFound,
            "TSIG_KEY_CONFLICT" => ErrorCode::TsigKeyConflict,
            "TSIG_KEY_IN_USE" => ErrorCode::TsigKeyInUse,
            "TSIG_GRANT_NOT_FOUND" => ErrorCode::TsigGrantNotFound,
            "TOKEN_GRANT_NOT_FOUND" => ErrorCode::TokenGrantNotFound,
            "DNSSEC_ALREADY_ENABLED" => ErrorCode::DnssecAlreadyEnabled,
            "DNSSEC_NOT_ENABLED" => ErrorCode::DnssecNotEnabled,
            "DNSSEC_ROLLOVER_IN_PROGRESS" => ErrorCode::DnssecRolloverInProgress,
            "DNSSEC_NO_ROLLOVER_IN_PROGRESS" => ErrorCode::DnssecNoRolloverInProgress,
            "DNSSEC_DS_PUBLISHED" => ErrorCode::DnssecDsPublished,
            "DNSSEC_DS_NOT_PUBLISHED" => ErrorCode::DnssecDsNotPublished,
            "DNSSEC_DS_UNVERIFIED" => ErrorCode::DnssecDsUnverified,
            "DNSSEC_POLICY_NOT_FOUND" => ErrorCode::DnssecPolicyNotFound,
            "DNSSEC_POLICY_CONFLICT" => ErrorCode::DnssecPolicyConflict,
            "DNSSEC_POLICY_IN_USE" => ErrorCode::DnssecPolicyInUse,
            "DNSSEC_SIGNING_FAILED" => ErrorCode::DnssecSigningFailed,
            "UNAUTHORIZED" => ErrorCode::Unauthorized,
            "INVALID_TOKEN" => ErrorCode::InvalidToken,
            "FORBIDDEN" => ErrorCode::Forbidden,
            "PAYLOAD_TOO_LARGE" => ErrorCode::PayloadTooLarge,
            "UNSUPPORTED_MEDIA_TYPE" => ErrorCode::UnsupportedMediaType,
            "INTERNAL" => ErrorCode::Internal,
            _ => return None,
        })
    }

    /// Whether the failure is the server's, not the requester's: what a
    /// transport reports as a server fault (SERVFAIL, 500) rather than a
    /// refusal.
    pub fn is_internal(&self) -> bool {
        matches!(self, ErrorCode::DnssecSigningFailed | ErrorCode::Internal)
    }
}

/// Error returned by the service layer: one variant per [`ErrorCode`], each
/// carrying the plain, user-facing message the error payload shows beside
/// the code. What a transport makes of a code — an HTTP status, an RCODE, an
/// exit code — is the transport's table, not this type's.
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
    TsigGrantNotFound(String),
    #[error("{0}")]
    TokenGrantNotFound(String),
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
            ServiceError::TsigGrantNotFound(_) => ErrorCode::TsigGrantNotFound,
            ServiceError::TokenGrantNotFound(_) => ErrorCode::TokenGrantNotFound,
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
    pub(crate) fn invalid_zone_field(message: impl fmt::Display) -> Self {
        ServiceError::InvalidZoneField(message.to_string())
    }

    /// Build an error for an invalid record owner name.
    pub(crate) fn invalid_record_name(message: impl fmt::Display) -> Self {
        ServiceError::InvalidRecordName(message.to_string())
    }

    /// Build an error for an invalid record value.
    pub(crate) fn invalid_record_value(message: impl fmt::Display) -> Self {
        ServiceError::InvalidRecordValue(message.to_string())
    }

    /// Build an error for a conflicting zone mutation.
    pub(crate) fn zone_conflict(message: impl fmt::Display) -> Self {
        ServiceError::ZoneConflict(message.to_string())
    }

    /// Build an error for a conflicting record mutation.
    pub(crate) fn record_conflict(message: impl fmt::Display) -> Self {
        ServiceError::RecordConflict(message.to_string())
    }

    /// Build an error for a request without valid authentication.
    pub fn unauthorized(message: impl fmt::Display) -> Self {
        ServiceError::Unauthorized(message.to_string())
    }

    /// Build an error for an invalid API token.
    pub(crate) fn invalid_token(message: impl fmt::Display) -> Self {
        ServiceError::InvalidToken(message.to_string())
    }

    /// Build an error for an operation the caller may not perform.
    pub(crate) fn forbidden(message: impl fmt::Display) -> Self {
        ServiceError::Forbidden(message.to_string())
    }

    /// Build an error for an internal service failure.
    pub fn internal(message: impl fmt::Display) -> Self {
        ServiceError::Internal {
            message: message.to_string(),
            source: None,
        }
    }

    /// Build an error naming the missing zone.
    pub(crate) fn zone_not_found(name: impl fmt::Display) -> Self {
        ServiceError::ZoneNotFound(format!("Zone with name '{}' not found", name))
    }

    /// Build an error identifying the missing record.
    pub(crate) fn record_not_found(id: RecordId) -> Self {
        ServiceError::RecordNotFound(format!("Record with id '{}' not found", id))
    }

    /// Build an error identifying the owner name that holds no record.
    pub(crate) fn record_not_found_at_name(
        zone_name: impl std::fmt::Display,
        name: impl std::fmt::Display,
    ) -> Self {
        ServiceError::RecordNotFound(format!(
            "No record named '{}' in zone '{}'",
            name, zone_name
        ))
    }

    /// Build an error for an owner name holding several records where only
    /// one may be touched. The message names the id rather than a front end's
    /// flag, because every transport reaches this.
    pub(crate) fn record_name_ambiguous(
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
    pub(crate) fn token_not_found(name: impl fmt::Display) -> Self {
        ServiceError::TokenNotFound(format!("API token with name '{}' not found", name))
    }

    /// Build an error for an API token name already in use.
    pub(crate) fn token_conflict(name: impl fmt::Display) -> Self {
        ServiceError::TokenConflict(format!("API token with name '{}' already exists", name))
    }

    /// Build an error naming the missing secondary.
    pub(crate) fn secondary_not_found(name: impl fmt::Display) -> Self {
        ServiceError::SecondaryNotFound(format!("Secondary with name '{}' not found", name))
    }

    /// Build an error for a secondary name or address already in use.
    pub(crate) fn secondary_conflict(message: impl fmt::Display) -> Self {
        ServiceError::SecondaryConflict(message.to_string())
    }

    /// Build an error naming the missing TSIG key.
    pub(crate) fn tsig_key_not_found(name: impl fmt::Display) -> Self {
        ServiceError::TsigKeyNotFound(format!("TSIG key with name '{}' not found", name))
    }

    /// Build an error for a TSIG key name already in use.
    pub(crate) fn tsig_key_conflict(name: impl fmt::Display) -> Self {
        ServiceError::TsigKeyConflict(format!("TSIG key with name '{}' already exists", name))
    }

    /// Build an error explaining that grants still reference a TSIG key.
    pub(crate) fn tsig_key_in_use(name: impl fmt::Display, grant_count: u64) -> Self {
        ServiceError::TsigKeyInUse(format!(
            "TSIG key '{}' still holds {} grant{}",
            name,
            grant_count,
            if grant_count == 1 { "" } else { "s" }
        ))
    }

    /// Build an error identifying the missing TSIG grant.
    pub(crate) fn tsig_grant_not_found(id: TsigGrantId) -> Self {
        ServiceError::TsigGrantNotFound(format!("TSIG grant with id '{}' not found", id))
    }

    /// Build an error identifying the missing token grant.
    pub(crate) fn token_grant_not_found(id: TokenGrantId) -> Self {
        ServiceError::TokenGrantNotFound(format!("Token grant with id '{}' not found", id))
    }

    /// Build an error for enabling DNSSEC on an already signed zone.
    pub(crate) fn dnssec_already_enabled(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecAlreadyEnabled(format!(
            "DNSSEC is already enabled for zone '{}'",
            zone_name
        ))
    }

    /// Build an error for an operation requiring DNSSEC on an unsigned zone.
    pub(crate) fn dnssec_not_enabled(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecNotEnabled(format!("DNSSEC is not enabled for zone '{}'", zone_name))
    }

    /// Build an error from what the signer could not do.
    pub(crate) fn dnssec_signing_failed(
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ServiceError::DnssecSigningFailed {
            source: Box::new(source),
        }
    }

    /// Build an error for a rollover already in progress.
    pub(crate) fn dnssec_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecRolloverInProgress(format!(
            "a key rollover is already in progress for zone '{}'",
            zone_name
        ))
    }

    /// Build an error for confirming a rollover that has not started.
    pub(crate) fn dnssec_no_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        ServiceError::DnssecNoRolloverInProgress(format!(
            "no key rollover is in progress for zone '{}'",
            zone_name
        ))
    }

    /// Build an error listing DS records that still block DNSSEC removal.
    pub(crate) fn dnssec_ds_published(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
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
    pub(crate) fn dnssec_ds_not_published(
        zone_name: impl fmt::Display,
        key_tags: &[KeyTag],
    ) -> Self {
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
    pub(crate) fn dnssec_ds_digest_unsupported(
        zone_name: impl fmt::Display,
        key_tags: &[KeyTag],
    ) -> Self {
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
    pub(crate) fn dnssec_ds_unverified(
        zone_name: impl fmt::Display,
        reason: impl fmt::Display,
    ) -> Self {
        ServiceError::DnssecDsUnverified(format!(
            "could not verify that the parent zone serves no DS for zone '{}': {}; set the \
                 zone's parent nameserver addresses, or skip the DS check",
            zone_name, reason
        ))
    }

    /// Build an error naming the missing DNSSEC policy.
    pub(crate) fn dnssec_policy_not_found(name: impl fmt::Display) -> Self {
        ServiceError::DnssecPolicyNotFound(format!("DNSSEC policy with name '{}' not found", name))
    }

    /// Build an error for a DNSSEC policy name already in use.
    pub(crate) fn dnssec_policy_conflict(name: impl fmt::Display) -> Self {
        ServiceError::DnssecPolicyConflict(format!(
            "DNSSEC policy with name '{}' already exists",
            name
        ))
    }

    /// Build an error explaining that zones still use a DNSSEC policy.
    pub(crate) fn dnssec_policy_in_use(name: impl fmt::Display, zone_count: u64) -> Self {
        ServiceError::DnssecPolicyInUse(format!(
            "DNSSEC policy '{}' is used by {} signed zone{}",
            name,
            zone_count,
            if zone_count == 1 { "" } else { "s" }
        ))
    }

    /// Build an error naming the missing zone serial.
    pub(crate) fn version_not_found(zone_name: impl fmt::Display, serial: Serial) -> Self {
        ServiceError::VersionNotFound(format!(
            "No version with serial '{}' for zone '{}'",
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
        // The CLI parses the code back off the daemon socket.
        assert_eq!(
            ErrorCode::parse(err.code().as_str()),
            Some(ErrorCode::DnssecSigningFailed)
        );
    }
}
