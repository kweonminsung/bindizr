//! Validate stored identifiers and descriptions against their column constraints.

use crate::error::ServiceError;

/// The width of a VARCHAR(255) column, in characters.
pub(crate) const MAX_COLUMN_TEXT_LEN: usize = 255;

/// Trim and lowercase a single URL path segment for consistent backend matching.
/// `what` names the field in errors.
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

/// Trim a description; empty clears it, while excess length and NUL yield input errors.
/// `error` supplies the field-specific rejection; PostgreSQL cannot store NUL.
pub(crate) fn normalize_description(
    value: Option<&str>,
    error: fn(String) -> ServiceError,
) -> Result<Option<String>, ServiceError> {
    let Some(description) = value.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };

    if description.chars().count() > MAX_COLUMN_TEXT_LEN {
        return Err(error(format!(
            "description must be {} characters or fewer",
            MAX_COLUMN_TEXT_LEN
        )));
    }
    if description.contains('\0') {
        return Err(error(
            "description must not contain NUL characters".to_string(),
        ));
    }

    Ok(Some(description.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{normalize_description, normalize_identifier};
    use crate::error::{ErrorCode, ServiceError};

    /// Verify that an identifier is trimmed and lowercased.
    #[test]
    fn normalize_identifier_trims_and_lowercases() {
        assert_eq!(
            normalize_identifier("  NS2.Example ", "name", 64).unwrap(),
            "ns2.example"
        );
    }

    /// Verify that an empty, over-long, or oddly spelled identifier is refused.
    #[test]
    fn normalize_identifier_rejects_empty_long_and_invalid_names() {
        for value in ["", "  ", "a b", "a/b", &"n".repeat(65)] {
            let error = normalize_identifier(value, "name", 64).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{value:?}");
        }
    }

    /// Verify that a description is trimmed, cleared when empty, counted in
    /// characters, and refused with NUL.
    #[test]
    fn normalize_description_trims_counts_characters_and_rejects_nul() {
        let normalize = |value| normalize_description(value, ServiceError::invalid_input);
        let widest = "é".repeat(255);
        let over = "é".repeat(256);

        assert_eq!(normalize(None).unwrap(), None);
        assert_eq!(normalize(Some("  ")).unwrap(), None);
        assert_eq!(normalize(Some(" note ")).unwrap().as_deref(), Some("note"));
        assert!(normalize(Some(widest.as_str())).is_ok());

        let too_long = normalize(Some(over.as_str())).unwrap_err();
        let nul = normalize(Some("a\0b")).unwrap_err();

        assert_eq!(too_long.code(), ErrorCode::InvalidInput);
        assert_eq!(nul.code(), ErrorCode::InvalidInput);
    }
}
