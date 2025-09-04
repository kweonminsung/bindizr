pub fn to_sqlite_url(file_path: &str) -> Result<String, String> {
    if file_path.trim().is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    // If the path is for an in-memory database or already has a scheme, use it directly.
    if file_path.starts_with("file:") || file_path.starts_with("sqlite:") {
        return Ok(file_path.to_string());
    }

    Ok(format!("sqlite:{}", file_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_sqlite_url() {
        // Test with absolute path
        let result = to_sqlite_url("/absolute/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:/absolute/path/to/database.db");

        // Test with relative path
        let result = to_sqlite_url("relative/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:relative/path/to/database.db");

        // Test with empty path
        let result = to_sqlite_url("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "File path cannot be empty");

        // Test with non-existent path
        let result = to_sqlite_url("non_existent_path/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:non_existent_path/database.db");

        // Test with in-memory database URL
        let result = to_sqlite_url("file::memory:?cache=shared");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "file::memory:?cache=shared");

        // Test with existing sqlite scheme
        let result = to_sqlite_url("sqlite:my_database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:my_database.db");
    }
}
