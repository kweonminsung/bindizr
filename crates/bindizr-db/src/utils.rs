pub(crate) fn to_sqlite_url(file_path: &str) -> Result<String, String> {
    let file_path = file_path.trim();
    if file_path.is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    if file_path.starts_with("sqlite:") {
        return Ok(file_path.to_string());
    }

    Ok(format!("sqlite:{}", file_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_sqlite_url_formats_plain_paths() {
        let result = to_sqlite_url("/absolute/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:/absolute/path/to/database.db");

        let result = to_sqlite_url("relative/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:relative/path/to/database.db");

        let result = to_sqlite_url("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "File path cannot be empty");

        let result = to_sqlite_url("file::memory:?cache=shared");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:file::memory:?cache=shared");

        let result = to_sqlite_url("sqlite:my_database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:my_database.db");
    }
}
