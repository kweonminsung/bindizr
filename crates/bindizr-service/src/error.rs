use std::fmt;

/// Machine-readable error codes exposed to API and CLI clients. Each code maps
/// to one HTTP status; the SCREAMING_SNAKE_CASE wire name is the public
/// contract.
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
    ZoneNotFound,
    RecordNotFound,
    TokenNotFound,
    VersionNotFound,
    TsigKeyNotFound,
    TsigKeyConflict,
    TsigKeyInUse,
    TsigPolicyNotFound,
    TokenPolicyNotFound,
    DnssecAlreadyEnabled,
    DnssecNotEnabled,
    DnssecRolloverInProgress,
    DnssecNoRolloverInProgress,
    DnssecPolicyNotFound,
    DnssecPolicyConflict,
    DnssecPolicyInUse,
    Unauthorized,
    InvalidToken,
    Forbidden,
    PayloadTooLarge,
    UnsupportedMediaType,
    Internal,
}

impl ErrorCode {
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
            ErrorCode::ZoneNotFound => "ZONE_NOT_FOUND",
            ErrorCode::RecordNotFound => "RECORD_NOT_FOUND",
            ErrorCode::TokenNotFound => "TOKEN_NOT_FOUND",
            ErrorCode::VersionNotFound => "VERSION_NOT_FOUND",
            ErrorCode::TsigKeyNotFound => "TSIG_KEY_NOT_FOUND",
            ErrorCode::TsigKeyConflict => "TSIG_KEY_CONFLICT",
            ErrorCode::TsigKeyInUse => "TSIG_KEY_IN_USE",
            ErrorCode::TsigPolicyNotFound => "TSIG_POLICY_NOT_FOUND",
            ErrorCode::TokenPolicyNotFound => "TOKEN_POLICY_NOT_FOUND",
            ErrorCode::DnssecAlreadyEnabled => "DNSSEC_ALREADY_ENABLED",
            ErrorCode::DnssecNotEnabled => "DNSSEC_NOT_ENABLED",
            ErrorCode::DnssecRolloverInProgress => "DNSSEC_ROLLOVER_IN_PROGRESS",
            ErrorCode::DnssecNoRolloverInProgress => "DNSSEC_NO_ROLLOVER_IN_PROGRESS",
            ErrorCode::DnssecPolicyNotFound => "DNSSEC_POLICY_NOT_FOUND",
            ErrorCode::DnssecPolicyConflict => "DNSSEC_POLICY_CONFLICT",
            ErrorCode::DnssecPolicyInUse => "DNSSEC_POLICY_IN_USE",
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
            "ZONE_NOT_FOUND" => ErrorCode::ZoneNotFound,
            "RECORD_NOT_FOUND" => ErrorCode::RecordNotFound,
            "TOKEN_NOT_FOUND" => ErrorCode::TokenNotFound,
            "VERSION_NOT_FOUND" => ErrorCode::VersionNotFound,
            "TSIG_KEY_NOT_FOUND" => ErrorCode::TsigKeyNotFound,
            "TSIG_KEY_CONFLICT" => ErrorCode::TsigKeyConflict,
            "TSIG_KEY_IN_USE" => ErrorCode::TsigKeyInUse,
            "TSIG_POLICY_NOT_FOUND" => ErrorCode::TsigPolicyNotFound,
            "TOKEN_POLICY_NOT_FOUND" => ErrorCode::TokenPolicyNotFound,
            "DNSSEC_ALREADY_ENABLED" => ErrorCode::DnssecAlreadyEnabled,
            "DNSSEC_NOT_ENABLED" => ErrorCode::DnssecNotEnabled,
            "DNSSEC_ROLLOVER_IN_PROGRESS" => ErrorCode::DnssecRolloverInProgress,
            "DNSSEC_NO_ROLLOVER_IN_PROGRESS" => ErrorCode::DnssecNoRolloverInProgress,
            "DNSSEC_POLICY_NOT_FOUND" => ErrorCode::DnssecPolicyNotFound,
            "DNSSEC_POLICY_CONFLICT" => ErrorCode::DnssecPolicyConflict,
            "DNSSEC_POLICY_IN_USE" => ErrorCode::DnssecPolicyInUse,
            "UNAUTHORIZED" => ErrorCode::Unauthorized,
            "INVALID_TOKEN" => ErrorCode::InvalidToken,
            "FORBIDDEN" => ErrorCode::Forbidden,
            "PAYLOAD_TOO_LARGE" => ErrorCode::PayloadTooLarge,
            "UNSUPPORTED_MEDIA_TYPE" => ErrorCode::UnsupportedMediaType,
            "INTERNAL" => ErrorCode::Internal,
            _ => return None,
        })
    }

    pub fn http_status(&self) -> u16 {
        match self {
            ErrorCode::InvalidInput
            | ErrorCode::InvalidZoneField
            | ErrorCode::InvalidRecordName
            | ErrorCode::InvalidRecordValue
            | ErrorCode::InvalidJsonBody => 400,
            ErrorCode::Unauthorized | ErrorCode::InvalidToken => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::ZoneNotFound
            | ErrorCode::RecordNotFound
            | ErrorCode::TokenNotFound
            | ErrorCode::VersionNotFound
            | ErrorCode::TsigKeyNotFound
            | ErrorCode::TsigPolicyNotFound
            | ErrorCode::TokenPolicyNotFound
            | ErrorCode::DnssecPolicyNotFound => 404,
            ErrorCode::ZoneConflict
            | ErrorCode::RecordConflict
            | ErrorCode::TokenConflict
            | ErrorCode::TsigKeyConflict
            | ErrorCode::TsigKeyInUse
            | ErrorCode::DnssecAlreadyEnabled
            | ErrorCode::DnssecNotEnabled
            | ErrorCode::DnssecRolloverInProgress
            | ErrorCode::DnssecNoRolloverInProgress
            | ErrorCode::DnssecPolicyConflict
            | ErrorCode::DnssecPolicyInUse => 409,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::UnsupportedMediaType => 415,
            ErrorCode::Internal => 500,
        }
    }
}

/// Error returned by the service layer. `message` is a plain, user-facing
/// description with no classification prefix; `code` carries the machine
/// classification (and the HTTP status via [`ErrorCode::http_status`]).
#[derive(Debug)]
pub struct ServiceError {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ServiceError {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    pub(crate) fn invalid_zone_field(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidZoneField, message)
    }

    pub(crate) fn invalid_record_name(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRecordName, message)
    }

    pub(crate) fn invalid_record_value(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRecordValue, message)
    }

    pub(crate) fn zone_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ZoneConflict, message)
    }

    pub(crate) fn record_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::RecordConflict, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, message)
    }

    pub(crate) fn invalid_token(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidToken, message)
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub(crate) fn zone_not_found(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::ZoneNotFound,
            format!("Zone with name '{}' not found", name.into()),
        )
    }

    pub(crate) fn record_not_found(id: i32) -> Self {
        Self::new(
            ErrorCode::RecordNotFound,
            format!("Record with id '{}' not found", id),
        )
    }

    pub(crate) fn token_not_found(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::TokenNotFound,
            format!("API token with name '{}' not found", name.into()),
        )
    }

    pub(crate) fn token_conflict(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::TokenConflict,
            format!("API token with name '{}' already exists", name.into()),
        )
    }

    pub(crate) fn tsig_key_not_found(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::TsigKeyNotFound,
            format!("TSIG key with name '{}' not found", name.into()),
        )
    }

    pub(crate) fn tsig_key_conflict(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::TsigKeyConflict,
            format!("TSIG key with name '{}' already exists", name.into()),
        )
    }

    pub(crate) fn tsig_key_in_use(name: impl Into<String>, policy_count: u64) -> Self {
        Self::new(
            ErrorCode::TsigKeyInUse,
            format!(
                "TSIG key '{}' is referenced by {} TSIG polic{}",
                name.into(),
                policy_count,
                if policy_count == 1 { "y" } else { "ies" }
            ),
        )
    }

    pub(crate) fn tsig_policy_not_found(id: i32) -> Self {
        Self::new(
            ErrorCode::TsigPolicyNotFound,
            format!("TSIG policy with id '{}' not found", id),
        )
    }

    pub(crate) fn token_policy_not_found(id: i32) -> Self {
        Self::new(
            ErrorCode::TokenPolicyNotFound,
            format!("Token policy with id '{}' not found", id),
        )
    }

    pub(crate) fn dnssec_already_enabled(zone_name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecAlreadyEnabled,
            format!("DNSSEC is already enabled for zone '{}'", zone_name.into()),
        )
    }

    pub(crate) fn dnssec_not_enabled(zone_name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecNotEnabled,
            format!("DNSSEC is not enabled for zone '{}'", zone_name.into()),
        )
    }

    pub(crate) fn dnssec_signing_failed(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::Internal,
            format!("DNSSEC signing failed: {}", message.into()),
        )
    }

    pub(crate) fn dnssec_rollover_in_progress(zone_name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecRolloverInProgress,
            format!(
                "a key rollover is already in progress for zone '{}'",
                zone_name.into()
            ),
        )
    }

    pub(crate) fn dnssec_no_rollover_in_progress(zone_name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecNoRolloverInProgress,
            format!(
                "no key rollover is in progress for zone '{}'",
                zone_name.into()
            ),
        )
    }

    pub(crate) fn dnssec_policy_not_found(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecPolicyNotFound,
            format!("DNSSEC policy with name '{}' not found", name.into()),
        )
    }

    pub(crate) fn dnssec_policy_conflict(name: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::DnssecPolicyConflict,
            format!("DNSSEC policy with name '{}' already exists", name.into()),
        )
    }

    pub(crate) fn dnssec_policy_in_use(name: impl Into<String>, zone_count: u64) -> Self {
        Self::new(
            ErrorCode::DnssecPolicyInUse,
            format!(
                "DNSSEC policy '{}' is used by {} signed zone{}",
                name.into(),
                zone_count,
                if zone_count == 1 { "" } else { "s" }
            ),
        )
    }

    pub(crate) fn version_not_found(zone_name: impl Into<String>, serial: i32) -> Self {
        Self::new(
            ErrorCode::VersionNotFound,
            format!(
                "No version with serial '{}' for zone '{}'",
                serial,
                zone_name.into()
            ),
        )
    }
}
