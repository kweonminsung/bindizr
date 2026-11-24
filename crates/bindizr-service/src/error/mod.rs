use std::fmt;

use bindizr_core::dns::Serial;
use bindizr_core::dns::dnssec::KeyTag;
use bindizr_core::model::record::RecordId;
use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_db::error::DatabaseError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Machine-readable error codes exposed to API and CLI clients. The
/// SCREAMING_SNAKE_CASE wire name is the public contract; what status a
/// code answers with is each transport's own table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::InvalidZoneField => "INVALID_ZONE_FIELD",
            Self::InvalidRecordName => "INVALID_RECORD_NAME",
            Self::InvalidRecordValue => "INVALID_RECORD_VALUE",
            Self::InvalidJsonBody => "INVALID_JSON_BODY",
            Self::ZoneConflict => "ZONE_CONFLICT",
            Self::RecordConflict => "RECORD_CONFLICT",
            Self::TokenConflict => "TOKEN_CONFLICT",
            Self::EndpointNotFound => "ENDPOINT_NOT_FOUND",
            Self::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            Self::ZoneNotFound => "ZONE_NOT_FOUND",
            Self::RecordNotFound => "RECORD_NOT_FOUND",
            Self::TokenNotFound => "TOKEN_NOT_FOUND",
            Self::VersionNotFound => "VERSION_NOT_FOUND",
            Self::SecondaryNotFound => "SECONDARY_NOT_FOUND",
            Self::SecondaryConflict => "SECONDARY_CONFLICT",
            Self::TsigKeyNotFound => "TSIG_KEY_NOT_FOUND",
            Self::TsigKeyConflict => "TSIG_KEY_CONFLICT",
            Self::TsigKeyInUse => "TSIG_KEY_IN_USE",
            Self::RoleNotFound => "ROLE_NOT_FOUND",
            Self::RoleConflict => "ROLE_CONFLICT",
            Self::RoleInUse => "ROLE_IN_USE",
            Self::RoleGrantNotFound => "ROLE_GRANT_NOT_FOUND",
            Self::DnssecAlreadyEnabled => "DNSSEC_ALREADY_ENABLED",
            Self::DnssecNotEnabled => "DNSSEC_NOT_ENABLED",
            Self::DnssecRolloverInProgress => "DNSSEC_ROLLOVER_IN_PROGRESS",
            Self::DnssecNoRolloverInProgress => "DNSSEC_NO_ROLLOVER_IN_PROGRESS",
            Self::DnssecDsPublished => "DNSSEC_DS_PUBLISHED",
            Self::DnssecDsNotPublished => "DNSSEC_DS_NOT_PUBLISHED",
            Self::DnssecDsUnverified => "DNSSEC_DS_UNVERIFIED",
            Self::DnssecPolicyNotFound => "DNSSEC_POLICY_NOT_FOUND",
            Self::DnssecPolicyConflict => "DNSSEC_POLICY_CONFLICT",
            Self::DnssecPolicyInUse => "DNSSEC_POLICY_IN_USE",
            Self::DnssecSigningFailed => "DNSSEC_SIGNING_FAILED",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::Forbidden => "FORBIDDEN",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            Self::Internal => "INTERNAL",
        }
    }

    /// Return whether the failure is the server's, not the requester's: what a
    /// transport reports as a server fault (SERVFAIL, 500) rather than a
    /// refusal.
    pub fn is_internal(self) -> bool {
        matches!(self, Self::DnssecSigningFailed | Self::Internal)
    }
}

/// Service failure with one variant per [`ErrorCode`] and a user-facing message.
/// Each transport maps the code to its own HTTP status, RCODE, or exit code.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{message}")]
    InvalidInput {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    #[error("{message}")]
    InvalidZoneField { message: String },
    #[error("{message}")]
    InvalidRecordName { message: String },
    #[error("{message}")]
    InvalidRecordValue { message: String },
    #[error("{message}")]
    InvalidJsonBody { message: String },
    #[error("{message}")]
    ZoneConflict { message: String },
    #[error("{message}")]
    RecordConflict { message: String },
    #[error("{message}")]
    TokenConflict { message: String },
    #[error("{message}")]
    EndpointNotFound { message: String },
    #[error("{message}")]
    MethodNotAllowed { message: String },
    #[error("{message}")]
    ZoneNotFound { message: String },
    #[error("{message}")]
    RecordNotFound { message: String },
    #[error("{message}")]
    TokenNotFound { message: String },
    #[error("{message}")]
    VersionNotFound { message: String },
    #[error("{message}")]
    SecondaryNotFound { message: String },
    #[error("{message}")]
    SecondaryConflict { message: String },
    #[error("{message}")]
    TsigKeyNotFound { message: String },
    #[error("{message}")]
    TsigKeyConflict { message: String },
    #[error("{message}")]
    TsigKeyInUse { message: String },
    #[error("{message}")]
    RoleNotFound { message: String },
    #[error("{message}")]
    RoleConflict { message: String },
    #[error("{message}")]
    RoleInUse { message: String },
    #[error("{message}")]
    RoleGrantNotFound { message: String },
    #[error("{message}")]
    DnssecAlreadyEnabled { message: String },
    #[error("{message}")]
    DnssecNotEnabled { message: String },
    #[error("{message}")]
    DnssecRolloverInProgress { message: String },
    #[error("{message}")]
    DnssecNoRolloverInProgress { message: String },
    #[error("{message}")]
    DnssecDsPublished { message: String },
    #[error("{message}")]
    DnssecDsNotPublished { message: String },
    #[error("{message}")]
    DnssecDsUnverified {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    #[error("{message}")]
    DnssecPolicyNotFound { message: String },
    #[error("{message}")]
    DnssecPolicyConflict { message: String },
    #[error("{message}")]
    DnssecPolicyInUse { message: String },
    /// A server fault named for alerting; the signer's error is its source.
    #[error("DNSSEC signing failed: {source}")]
    DnssecSigningFailed {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("{message}")]
    Unauthorized { message: String },
    #[error("{message}")]
    InvalidToken { message: String },
    #[error("{message}")]
    Forbidden { message: String },
    #[error("{message}")]
    PayloadTooLarge { message: String },
    #[error("{message}")]
    UnsupportedMediaType { message: String },
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
    /// Return the machine-readable code of this error, the wire's classification.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidInput { .. } => ErrorCode::InvalidInput,
            Self::InvalidZoneField { .. } => ErrorCode::InvalidZoneField,
            Self::InvalidRecordName { .. } => ErrorCode::InvalidRecordName,
            Self::InvalidRecordValue { .. } => ErrorCode::InvalidRecordValue,
            Self::InvalidJsonBody { .. } => ErrorCode::InvalidJsonBody,
            Self::ZoneConflict { .. } => ErrorCode::ZoneConflict,
            Self::RecordConflict { .. } => ErrorCode::RecordConflict,
            Self::TokenConflict { .. } => ErrorCode::TokenConflict,
            Self::EndpointNotFound { .. } => ErrorCode::EndpointNotFound,
            Self::MethodNotAllowed { .. } => ErrorCode::MethodNotAllowed,
            Self::ZoneNotFound { .. } => ErrorCode::ZoneNotFound,
            Self::RecordNotFound { .. } => ErrorCode::RecordNotFound,
            Self::TokenNotFound { .. } => ErrorCode::TokenNotFound,
            Self::VersionNotFound { .. } => ErrorCode::VersionNotFound,
            Self::SecondaryNotFound { .. } => ErrorCode::SecondaryNotFound,
            Self::SecondaryConflict { .. } => ErrorCode::SecondaryConflict,
            Self::TsigKeyNotFound { .. } => ErrorCode::TsigKeyNotFound,
            Self::TsigKeyConflict { .. } => ErrorCode::TsigKeyConflict,
            Self::TsigKeyInUse { .. } => ErrorCode::TsigKeyInUse,
            Self::RoleNotFound { .. } => ErrorCode::RoleNotFound,
            Self::RoleConflict { .. } => ErrorCode::RoleConflict,
            Self::RoleInUse { .. } => ErrorCode::RoleInUse,
            Self::RoleGrantNotFound { .. } => ErrorCode::RoleGrantNotFound,
            Self::DnssecAlreadyEnabled { .. } => ErrorCode::DnssecAlreadyEnabled,
            Self::DnssecNotEnabled { .. } => ErrorCode::DnssecNotEnabled,
            Self::DnssecRolloverInProgress { .. } => ErrorCode::DnssecRolloverInProgress,
            Self::DnssecNoRolloverInProgress { .. } => ErrorCode::DnssecNoRolloverInProgress,
            Self::DnssecDsPublished { .. } => ErrorCode::DnssecDsPublished,
            Self::DnssecDsNotPublished { .. } => ErrorCode::DnssecDsNotPublished,
            Self::DnssecDsUnverified { .. } => ErrorCode::DnssecDsUnverified,
            Self::DnssecPolicyNotFound { .. } => ErrorCode::DnssecPolicyNotFound,
            Self::DnssecPolicyConflict { .. } => ErrorCode::DnssecPolicyConflict,
            Self::DnssecPolicyInUse { .. } => ErrorCode::DnssecPolicyInUse,
            Self::DnssecSigningFailed { .. } => ErrorCode::DnssecSigningFailed,
            Self::Unauthorized { .. } => ErrorCode::Unauthorized,
            Self::InvalidToken { .. } => ErrorCode::InvalidToken,
            Self::Forbidden { .. } => ErrorCode::Forbidden,
            Self::PayloadTooLarge { .. } => ErrorCode::PayloadTooLarge,
            Self::UnsupportedMediaType { .. } => ErrorCode::UnsupportedMediaType,
            Self::Internal { .. } => ErrorCode::Internal,
        }
    }
}

impl ServiceError {
    /// Build an error for invalid request input.
    pub fn invalid_input(message: impl fmt::Display) -> Self {
        Self::InvalidInput {
            message: message.to_string(),
            source: None,
        }
    }

    /// Build an error for invalid input, keeping the cause when an external input
    /// could not be retrieved or interpreted.
    pub fn invalid_input_with_source(
        message: impl fmt::Display,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::InvalidInput {
            message: message.to_string(),
            source: Some(Box::new(source)),
        }
    }

    /// Build an error for an invalid zone field.
    pub fn invalid_zone_field(message: impl fmt::Display) -> Self {
        Self::InvalidZoneField {
            message: message.to_string(),
        }
    }

    /// Build an error for an invalid record owner name.
    pub fn invalid_record_name(message: impl fmt::Display) -> Self {
        Self::InvalidRecordName {
            message: message.to_string(),
        }
    }

    /// Build an error for an invalid record value.
    pub fn invalid_record_value(message: impl fmt::Display) -> Self {
        Self::InvalidRecordValue {
            message: message.to_string(),
        }
    }

    /// Build an error for a conflicting zone mutation.
    pub fn zone_conflict(message: impl fmt::Display) -> Self {
        Self::ZoneConflict {
            message: message.to_string(),
        }
    }

    /// Build an error for a conflicting record mutation.
    pub fn record_conflict(message: impl fmt::Display) -> Self {
        Self::RecordConflict {
            message: message.to_string(),
        }
    }

    /// Build an error for a request without valid authentication.
    pub fn unauthorized(message: impl fmt::Display) -> Self {
        Self::Unauthorized {
            message: message.to_string(),
        }
    }

    /// Build an error for an invalid API token.
    pub fn invalid_token(message: impl fmt::Display) -> Self {
        Self::InvalidToken {
            message: message.to_string(),
        }
    }

    /// Build an error for an operation the caller may not perform.
    pub fn forbidden(message: impl fmt::Display) -> Self {
        Self::Forbidden {
            message: message.to_string(),
        }
    }

    /// Build an error for an internal service failure.
    pub fn internal(message: impl fmt::Display) -> Self {
        Self::Internal {
            message: message.to_string(),
            source: None,
        }
    }

    /// Build an error for an internal failure, keeping it as the source of an
    /// operation-specific message.
    pub fn internal_with_source(
        message: impl fmt::Display,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Internal {
            message: message.to_string(),
            source: Some(Box::new(source)),
        }
    }

    /// Build an error naming the missing zone.
    pub fn zone_not_found(zone_name: impl fmt::Display) -> Self {
        Self::ZoneNotFound {
            message: format!("zone with name '{zone_name}' not found"),
        }
    }

    /// Build an error identifying the missing record.
    pub fn record_not_found(record_id: RecordId) -> Self {
        Self::RecordNotFound {
            message: format!("record with id '{record_id}' not found"),
        }
    }

    /// Build an error identifying the owner name that holds no record.
    pub fn record_not_found_at_name(zone_name: impl fmt::Display, name: impl fmt::Display) -> Self {
        Self::RecordNotFound {
            message: format!("no record named '{name}' in zone '{zone_name}'"),
        }
    }

    /// Build an error for an ambiguous owner name, asking for a record id in
    /// transport-neutral terms.
    pub fn record_name_ambiguous(
        zone_name: impl fmt::Display,
        name: impl fmt::Display,
        matched: usize,
    ) -> Self {
        Self::invalid_input(format!(
            "{matched} records are named '{name}' in zone '{zone_name}'; address one by its id"
        ))
    }

    /// Build an error naming the missing API token.
    pub fn token_not_found(name: impl fmt::Display) -> Self {
        Self::TokenNotFound {
            message: format!("API token with name '{name}' not found"),
        }
    }

    /// Build an error for an API token name already in use.
    pub fn token_conflict(name: impl fmt::Display) -> Self {
        Self::TokenConflict {
            message: format!("API token with name '{name}' already exists"),
        }
    }

    /// Build an error naming the missing secondary.
    pub fn secondary_not_found(name: impl fmt::Display) -> Self {
        Self::SecondaryNotFound {
            message: format!("secondary with name '{name}' not found"),
        }
    }

    /// Build an error for a secondary name or address already in use.
    pub fn secondary_conflict(message: impl fmt::Display) -> Self {
        Self::SecondaryConflict {
            message: message.to_string(),
        }
    }

    /// Build an error naming the missing TSIG key.
    pub fn tsig_key_not_found(name: impl fmt::Display) -> Self {
        Self::TsigKeyNotFound {
            message: format!("TSIG key with name '{name}' not found"),
        }
    }

    /// Build an error for a TSIG key name already in use.
    pub fn tsig_key_conflict(name: impl fmt::Display) -> Self {
        Self::TsigKeyConflict {
            message: format!("TSIG key with name '{name}' already exists"),
        }
    }

    /// Build an error naming the missing role.
    pub fn role_not_found(name: impl fmt::Display) -> Self {
        Self::RoleNotFound {
            message: format!("role with name '{name}' not found"),
        }
    }

    /// Build an error for a role name already in use.
    pub fn role_conflict(name: impl fmt::Display) -> Self {
        Self::RoleConflict {
            message: format!("role with name '{name}' already exists"),
        }
    }

    /// Build an error explaining that credentials still authenticate into a role.
    pub fn role_in_use(name: impl fmt::Display, tokens: &[String], tsig_keys: &[String]) -> Self {
        let mut holders = Vec::new();

        if !tokens.is_empty() {
            let noun = if tokens.len() == 1 {
                "API token"
            } else {
                "API tokens"
            };
            holders.push(format!("{noun} {}", tokens.join(", ")));
        }

        if !tsig_keys.is_empty() {
            let noun = if tsig_keys.len() == 1 {
                "TSIG key"
            } else {
                "TSIG keys"
            };
            holders.push(format!("{noun} {}", tsig_keys.join(", ")));
        }

        Self::RoleInUse {
            message: format!("role '{name}' is still held by {}", holders.join(" and ")),
        }
    }

    /// Build an error identifying the missing role grant.
    pub fn role_grant_not_found(grant_id: RoleGrantId) -> Self {
        Self::RoleGrantNotFound {
            message: format!("role grant with id '{grant_id}' not found"),
        }
    }

    /// Build an error for enabling DNSSEC on an already signed zone.
    pub fn dnssec_already_enabled(zone_name: impl fmt::Display) -> Self {
        Self::DnssecAlreadyEnabled {
            message: format!("DNSSEC is already enabled for zone '{zone_name}'"),
        }
    }

    /// Build an error for an operation requiring DNSSEC on an unsigned zone.
    pub fn dnssec_not_enabled(zone_name: impl fmt::Display) -> Self {
        Self::DnssecNotEnabled {
            message: format!("DNSSEC is not enabled for zone '{zone_name}'"),
        }
    }

    /// Build an error from what the signer could not do.
    pub fn dnssec_signing_failed(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::DnssecSigningFailed {
            source: Box::new(source),
        }
    }

    /// Build an error for a rollover already in progress.
    pub fn dnssec_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        Self::DnssecRolloverInProgress {
            message: format!("a key rollover is already in progress for zone '{zone_name}'"),
        }
    }

    /// Build an error for confirming a rollover while no published key awaits
    /// promotion; a predecessor still retiring does not count.
    pub fn dnssec_no_rollover_in_progress(zone_name: impl fmt::Display) -> Self {
        Self::DnssecNoRolloverInProgress {
            message: format!("no published key awaits promotion in zone '{zone_name}'"),
        }
    }

    /// Build an error listing DS records that still block DNSSEC removal.
    pub fn dnssec_ds_published(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        Self::DnssecDsPublished {
            message: format!(
                "the parent zone still serves DS records for zone '{zone_name}' (key tag{} {}); remove \
                 them and wait out their TTL before disabling DNSSEC, or skip the DS check",
                if key_tags.len() == 1 {
                    ""
                } else {
                    "s"
                },
                key_tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Build an error listing DS records still required for key promotion.
    pub fn dnssec_ds_not_published(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        Self::DnssecDsNotPublished {
            message: format!(
                "the parent zone serves no DS yet for key tag{} {} of zone '{zone_name}'; register it \
                 and wait out the DS TTL before confirming, or skip the DS check",
                if key_tags.len() == 1 {
                    ""
                } else {
                    "s"
                },
                key_tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Build an error for parent DS digests that cannot be verified.
    pub fn dnssec_ds_digest_unsupported(zone_name: impl fmt::Display, key_tags: &[KeyTag]) -> Self {
        Self::DnssecDsUnverified {
            message: format!(
                "the parent zone serves a DS for key tag{} {} of zone '{zone_name}', but only in digest \
                 types bindizr cannot compute, so the match cannot be confirmed; ask the parent \
                 to publish SHA-256, or skip the DS check",
                if key_tags.len() == 1 {
                    ""
                } else {
                    "s"
                },
                key_tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            source: None,
        }
    }

    /// Build an error explaining why the parent DS check could not finish.
    pub fn dnssec_ds_unverified(
        zone_name: impl fmt::Display,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::DnssecDsUnverified {
            message: format!(
                "could not ask the parent zone for the DS of zone '{zone_name}': {source}"
            ),
            source: Some(Box::new(source)),
        }
    }

    /// Build an error naming the missing DNSSEC policy.
    pub fn dnssec_policy_not_found(name: impl fmt::Display) -> Self {
        Self::DnssecPolicyNotFound {
            message: format!("DNSSEC policy with name '{name}' not found"),
        }
    }

    /// Build an error for a DNSSEC policy name already in use.
    pub fn dnssec_policy_conflict(name: impl fmt::Display) -> Self {
        Self::DnssecPolicyConflict {
            message: format!("DNSSEC policy with name '{name}' already exists"),
        }
    }

    /// Build an error explaining that zones still use a DNSSEC policy.
    pub fn dnssec_policy_in_use(name: impl fmt::Display, zone_count: u64) -> Self {
        Self::DnssecPolicyInUse {
            message: format!(
                "DNSSEC policy '{name}' is used by {zone_count} signed zone{}",
                if zone_count == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        }
    }

    /// Build an error naming the missing zone serial.
    pub fn version_not_found(zone_name: impl fmt::Display, serial: Serial) -> Self {
        Self::VersionNotFound {
            message: format!("no version with serial '{serial}' for zone '{zone_name}'"),
        }
    }
}

/// Unclassified database errors, a stored value that does not decode among
/// them, are internal failures. Call sites map UNIQUE/FK conflicts where their
/// meaning is known.
impl From<DatabaseError> for ServiceError {
    /// Build an internal error wrapping a database error.
    fn from(error: DatabaseError) -> Self {
        Self::Internal {
            message: format!("database error: {error}"),
            source: Some(Box::new(error)),
        }
    }
}

#[cfg(test)]
mod tests;
