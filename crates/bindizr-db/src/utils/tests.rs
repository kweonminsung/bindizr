use super::*;

#[test]
fn to_sqlite_url_formats_plain_paths() {
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

    // Test with in-memory database URL
    let result = to_sqlite_url("file::memory:?cache=shared");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "sqlite:file::memory:?cache=shared");

    // Test with existing sqlite scheme
    let result = to_sqlite_url("sqlite:my_database.db");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "sqlite:my_database.db");
}
