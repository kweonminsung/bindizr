use std::path::Path;

pub fn to_sqlite_url(file_path: &str) -> Result<String, String> {
    if file_path.trim().is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    let path = Path::new(file_path);

    let full_path = if path.exists() {
        match path.canonicalize() {
            Ok(p) => p,
            Err(_) => path.to_path_buf(),
        }
    } else {
        path.to_path_buf()
    };

    let url = if full_path.is_absolute() {
        format!("sqlite://{}", full_path.display())
    } else {
        format!("sqlite://{}", file_path)
    };

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_sqlite_url() {
        // Test with absolute path
        let result = to_sqlite_url("/absolute/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite:///absolute/path/to/database.db");

        // Test with relative path
        let result = to_sqlite_url("relative/path/to/database.db");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sqlite://relative/path/to/database.db");

        // Test with empty path
        let result = to_sqlite_url("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "File path cannot be empty");

        // Test with non-existent path
        let result = to_sqlite_url("non_existent_path/database.db");
        assert!(result.is_ok());
        assert!(
            result
                .unwrap()
                .starts_with("sqlite://non_existent_path/database.db")
        );
    }
}
