use std::fmt;

/// Machine-readable error codes exposed to API and CLI clients. Each code maps
/// to one HTTP status; the SCREAMING_SNAKE_CASE wire name is the public
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInput,
    InvalidZone,
    InvalidRecordName,
    InvalidRecordValue,
    InvalidJsonBody,
    ZoneConflict,
    RecordConflict,
    ZoneNotFound,
    RecordNotFound,
    TokenNotFound,
    SnapshotNotFound,
    TsigKeyNotFound,
    TsigKeyConflict,
    TsigKeyInUse,
    TsigPolicyNotFound,
    Unauthorized,
    InvalidToken,
    PayloadTooLarge,
    UnsupportedMediaType,
    Internal,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InvalidInput => "INVALID_INPUT",
            ErrorCode::InvalidZone => "INVALID_ZONE",
            ErrorCode::InvalidRecordName => "INVALID_RECORD_NAME",
            ErrorCode::InvalidRecordValue => "INVALID_RECORD_VALUE",
            ErrorCode::InvalidJsonBody => "INVALID_JSON_BODY",
            ErrorCode::ZoneConflict => "ZONE_CONFLICT",
            ErrorCode::RecordConflict => "RECORD_CONFLICT",
            ErrorCode::ZoneNotFound => "ZONE_NOT_FOUND",
            ErrorCode::RecordNotFound => "RECORD_NOT_FOUND",
            ErrorCode::TokenNotFound => "TOKEN_NOT_FOUND",
            ErrorCode::SnapshotNotFound => "SNAPSHOT_NOT_FOUND",
            ErrorCode::TsigKeyNotFound => "TSIG_KEY_NOT_FOUND",
            ErrorCode::TsigKeyConflict => "TSIG_KEY_CONFLICT",
            ErrorCode::TsigKeyInUse => "TSIG_KEY_IN_USE",
            ErrorCode::TsigPolicyNotFound => "TSIG_POLICY_NOT_FOUND",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::InvalidToken => "INVALID_TOKEN",
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
            "INVALID_ZONE" => ErrorCode::InvalidZone,
            "INVALID_RECORD_NAME" => ErrorCode::InvalidRecordName,
            "INVALID_RECORD_VALUE" => ErrorCode::InvalidRecordValue,
            "INVALID_JSON_BODY" => ErrorCode::InvalidJsonBody,
            "ZONE_CONFLICT" => ErrorCode::ZoneConflict,
            "RECORD_CONFLICT" => ErrorCode::RecordConflict,
            "ZONE_NOT_FOUND" => ErrorCode::ZoneNotFound,
            "RECORD_NOT_FOUND" => ErrorCode::RecordNotFound,
            "TOKEN_NOT_FOUND" => ErrorCode::TokenNotFound,
            "SNAPSHOT_NOT_FOUND" => ErrorCode::SnapshotNotFound,
            "TSIG_KEY_NOT_FOUND" => ErrorCode::TsigKeyNotFound,
            "TSIG_KEY_CONFLICT" => ErrorCode::TsigKeyConflict,
            "TSIG_KEY_IN_USE" => ErrorCode::TsigKeyInUse,
            "TSIG_POLICY_NOT_FOUND" => ErrorCode::TsigPolicyNotFound,
            "UNAUTHORIZED" => ErrorCode::Unauthorized,
            "INVALID_TOKEN" => ErrorCode::InvalidToken,
            "PAYLOAD_TOO_LARGE" => ErrorCode::PayloadTooLarge,
            "UNSUPPORTED_MEDIA_TYPE" => ErrorCode::UnsupportedMediaType,
            "INTERNAL" => ErrorCode::Internal,
            _ => return None,
        })
    }

    pub fn http_status(&self) -> u16 {
        match self {
            ErrorCode::InvalidInput
            | ErrorCode::InvalidZone
            | ErrorCode::InvalidRecordName
            | ErrorCode::InvalidRecordValue
            | ErrorCode::InvalidJsonBody => 400,
            ErrorCode::Unauthorized | ErrorCode::InvalidToken => 401,
            ErrorCode::ZoneNotFound
            | ErrorCode::RecordNotFound
            | ErrorCode::TokenNotFound
            | ErrorCode::SnapshotNotFound
            | ErrorCode::TsigKeyNotFound
            | ErrorCode::TsigPolicyNotFound => 404,
            ErrorCode::ZoneConflict
            | ErrorCode::RecordConflict
            | ErrorCode::TsigKeyConflict
            | ErrorCode::TsigKeyInUse => 409,
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

    pub fn invalid_zone(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidZone, message)
    }

    pub fn invalid_record_name(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRecordName, message)
    }

    pub fn invalid_record_value(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRecordValue, message)
    }

    pub fn zone_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ZoneConflict, message)
    }

    pub fn record_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::RecordConflict, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, message)
    }

    pub fn invalid_token(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidToken, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn zone_not_found(name: &str) -> Self {
        Self::new(
            ErrorCode::ZoneNotFound,
            format!("Zone with name '{}' not found", name),
        )
    }

    pub fn record_not_found(id: i32) -> Self {
        Self::new(
            ErrorCode::RecordNotFound,
            format!("Record with id '{}' not found", id),
        )
    }

    pub fn token_not_found() -> Self {
        Self::new(ErrorCode::TokenNotFound, "Token not found")
    }

    pub fn tsig_key_not_found(name: &str) -> Self {
        Self::new(
            ErrorCode::TsigKeyNotFound,
            format!("TSIG key with name '{}' not found", name),
        )
    }

    pub fn tsig_key_conflict(name: &str) -> Self {
        Self::new(
            ErrorCode::TsigKeyConflict,
            format!("TSIG key with name '{}' already exists", name),
        )
    }

    pub fn tsig_key_in_use(name: &str, policy_count: u64) -> Self {
        Self::new(
            ErrorCode::TsigKeyInUse,
            format!(
                "TSIG key '{}' is referenced by {} TSIG polic{}",
                name,
                policy_count,
                if policy_count == 1 { "y" } else { "ies" }
            ),
        )
    }

    pub fn tsig_policy_not_found(id: i32) -> Self {
        Self::new(
            ErrorCode::TsigPolicyNotFound,
            format!("TSIG policy with id '{}' not found", id),
        )
    }

    pub fn snapshot_not_found(zone_name: &str, serial: i32) -> Self {
        Self::new(
            ErrorCode::SnapshotNotFound,
            format!(
                "No snapshot with serial '{}' for zone '{}'",
                serial, zone_name
            ),
        )
    }
}
