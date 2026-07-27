use bindizr_service::error::ErrorCode;

/// Error surfaced to the CLI user: the daemon's message plus, when the daemon
/// sent a machine-readable code, an actionable hint derived from it.
#[derive(Debug)]
pub(crate) struct CliError {
    pub code: Option<ErrorCode>,
    pub message: String,
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

impl CliError {
    pub(crate) fn hint(&self) -> Option<&'static str> {
        match self.code? {
            ErrorCode::ZoneNotFound => Some("Run 'bindizr zone list' to see available zones."),
            ErrorCode::RecordNotFound => {
                Some("Run 'bindizr record list' to see available records.")
            }
            ErrorCode::TokenNotFound => Some("Run 'bindizr token list' to see available tokens."),
            ErrorCode::SnapshotNotFound => {
                Some("Run 'bindizr zone snapshots <NAME>' to see available serials.")
            }
            ErrorCode::Internal => Some("Check the daemon logs for details."),
            _ => None,
        }
    }
}
