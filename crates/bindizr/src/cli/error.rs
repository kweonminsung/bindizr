use bindizr_service::error::ErrorCode;

/// Error surfaced to the CLI user: the daemon's message plus, when the daemon
/// sent a machine-readable code, an actionable hint derived from it.
#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) code: Option<ErrorCode>,
    pub(crate) message: String,
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        CliError {
            code: None,
            message,
        }
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        CliError {
            code: None,
            message: message.to_string(),
        }
    }
}

/// 2 is left to clap's usage errors.
const EXIT_FAILURE: i32 = 1;
const EXIT_NOT_FOUND: i32 = 3;
const EXIT_CONFLICT: i32 = 4;
const EXIT_DENIED: i32 = 5;

impl CliError {
    /// Derived from `http_status`, so a new code needs no second list here.
    pub(crate) fn exit_code(&self) -> i32 {
        match self.code.map(|code| code.http_status()) {
            Some(404) => EXIT_NOT_FOUND,
            Some(409) => EXIT_CONFLICT,
            Some(401 | 403) => EXIT_DENIED,
            _ => EXIT_FAILURE,
        }
    }

    /// Every code is spelled out, so a new one has to decide whether it can
    /// point at a command instead of silently defaulting to no hint.
    pub(crate) fn hint(&self) -> Option<&'static str> {
        match self.code? {
            ErrorCode::ZoneNotFound => Some("Run 'bindizr zone list' to see available zones."),
            ErrorCode::RecordNotFound => {
                Some("Run 'bindizr record list' to see available records.")
            }
            ErrorCode::TokenNotFound => Some("Run 'bindizr token list' to see available tokens."),
            ErrorCode::VersionNotFound => {
                Some("Run 'bindizr zone version list <NAME>' to see available serials.")
            }
            ErrorCode::TsigKeyNotFound => {
                Some("Run 'bindizr tsig-key list' to see available keys.")
            }
            ErrorCode::DnssecPolicyNotFound => {
                Some("Run 'bindizr dnssec-policy list' to see available policies.")
            }
            ErrorCode::TsigKeyInUse => Some(
                "Run 'bindizr tsig-key grants <NAME>' and revoke each one before deleting the key.",
            ),
            ErrorCode::DnssecPolicyInUse => Some(
                "Move those zones onto another policy with 'bindizr dnssec set --policy', or disable DNSSEC on them.",
            ),
            ErrorCode::DnssecNotEnabled => Some(
                "Run 'bindizr dnssec enable <NAME> --parent-ns-addrs <ADDRS>' to sign the zone first.",
            ),
            ErrorCode::DnssecRolloverInProgress => Some(
                "Run 'bindizr dnssec status <NAME>' to see which key is rolling and what it waits on.",
            ),
            ErrorCode::DnssecNoRolloverInProgress => {
                Some("Start one with 'bindizr dnssec rollover start <NAME>'.")
            }
            ErrorCode::DnssecSigningFailed => Some(
                "Check the daemon logs; 'bindizr dnssec status <NAME>' shows whether the zone is still signed.",
            ),
            ErrorCode::Internal => Some("Check the daemon logs for details."),
            ErrorCode::TsigGrantNotFound => {
                Some("Run 'bindizr tsig-key grants <NAME>' to see a key's grant IDs.")
            }
            ErrorCode::TokenGrantNotFound => {
                Some("Run 'bindizr token grants <NAME>' to see a token's grant IDs.")
            }
            ErrorCode::DnssecAlreadyEnabled => Some(
                "Run 'bindizr dnssec status <NAME>' to see the settings, or 'bindizr dnssec set' to change them.",
            ),
            ErrorCode::InvalidRecordName => Some(
                "Record names are relative to the zone: '@' is the apex, and a fully qualified name must end in the zone.",
            ),
            // The CLI speaks the daemon socket as a global caller, so no
            // transport or token error can reach it.
            ErrorCode::InvalidJsonBody
            | ErrorCode::EndpointNotFound
            | ErrorCode::MethodNotAllowed
            | ErrorCode::Unauthorized
            | ErrorCode::InvalidToken
            | ErrorCode::Forbidden
            | ErrorCode::PayloadTooLarge
            | ErrorCode::UnsupportedMediaType => None,
            // The daemon's message already names the remedy for these, so a
            // hint could only restate it.
            ErrorCode::InvalidInput
            | ErrorCode::InvalidZoneField
            | ErrorCode::InvalidRecordValue
            | ErrorCode::ZoneConflict
            | ErrorCode::RecordConflict
            | ErrorCode::TokenConflict
            | ErrorCode::TsigKeyConflict
            | ErrorCode::DnssecPolicyConflict
            | ErrorCode::DnssecDsPublished
            | ErrorCode::DnssecDsNotPublished
            | ErrorCode::DnssecDsUnverified
            | ErrorCode::DnssecStateChanged => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_separate_the_classes_a_script_branches_on() {
        let code = |code| {
            CliError {
                code: Some(code),
                message: String::new(),
            }
            .exit_code()
        };

        assert_eq!(code(ErrorCode::ZoneNotFound), EXIT_NOT_FOUND);
        assert_eq!(code(ErrorCode::RecordConflict), EXIT_CONFLICT);
        assert_eq!(code(ErrorCode::Forbidden), EXIT_DENIED);
        assert_eq!(code(ErrorCode::InvalidInput), EXIT_FAILURE);
        // An unreachable daemon sends no code at all.
        assert_eq!(
            CliError::from("daemon is not running").exit_code(),
            EXIT_FAILURE
        );
    }
}
