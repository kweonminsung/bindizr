//! The plain identifiers that name tokens, secondaries, and DNSSEC policies:
//! one URL path segment, lowercased so one name means one row on every
//! backend (MySQL compares case-insensitively).

use crate::error::ServiceError;

/// Trim and lowercase a plain identifier, refusing an empty one, one longer
/// than `max_len`, or one with a character outside letters, digits, `.`,
/// `_`, and `-`. `what` names the field in the error.
pub(crate) fn normalize_identifier(
    value: &str,
    what: &str,
    max_len: usize,
) -> Result<String, ServiceError> {
    let name = value.trim().to_lowercase();
    if name.is_empty() {
        return Err(ServiceError::invalid_input(format!(
            "{} must not be empty",
            what
        )));
    }
    if name.len() > max_len {
        return Err(ServiceError::invalid_input(format!(
            "{} must be {} characters or fewer",
            what, max_len
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ServiceError::invalid_input(format!(
            "{} may contain only letters, digits, '.', '_', and '-'",
            what
        )));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::normalize_identifier;
    use crate::error::ErrorCode;

    /// Verify that an identifier is trimmed and lowercased.
    #[test]
    fn trims_and_lowercases() {
        assert_eq!(
            normalize_identifier("  NS2.Example ", "name", 64).unwrap(),
            "ns2.example"
        );
    }

    /// Verify that an empty, over-long, or oddly spelled identifier is refused.
    #[test]
    fn rejects_empty_long_and_odd_identifiers() {
        for value in ["", "  ", "a b", "a/b", &"n".repeat(65)] {
            let err = normalize_identifier(value, "name", 64).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{value:?}");
        }
    }
}
