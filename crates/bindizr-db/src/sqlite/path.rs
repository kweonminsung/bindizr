//! SQLite file paths, parent directories, and connection URLs.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::{fs, io};

use crate::error::DatabaseError;

/// Create a SQLite file's parent directory with mode 0700 to protect TSIG secrets.
/// Leave existing directories, bare filenames, and `sqlite:`/`file:` URIs alone.
pub(crate) fn create_parent_dir(file_path: &str) -> Result<(), DatabaseError> {
    let file_path = file_path.trim();

    if file_path.starts_with("sqlite:") || file_path.starts_with("file:") {
        return Ok(());
    }

    let Some(parent) = Path::new(file_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    else {
        return Ok(());
    };

    if parent.is_dir() {
        return Ok(());
    }

    let failed = |source: io::Error| DatabaseError::CreateSqliteDir {
        path: parent.to_path_buf(),
        source,
    };
    fs::create_dir_all(parent).map_err(failed)?;

    fs::set_permissions(parent, Permissions::from_mode(0o700)).map_err(failed)
}

/// Convert a configured SQLite path into a SQLx connection URL.
pub(crate) fn to_url(file_path: &str) -> Result<String, DatabaseError> {
    let file_path = file_path.trim();

    if file_path.is_empty() {
        return Err(DatabaseError::EmptySqlitePath);
    }

    if file_path.starts_with("sqlite:") {
        return Ok(file_path.to_string());
    }

    Ok(format!("sqlite:{file_path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the SQLite directory is created only where the path names one.
    #[test]
    fn create_parent_dir_makes_the_directory_a_path_names() {
        let temp = tempfile::tempdir().expect("temp dir");
        let nested = temp.path().join("state").join("deeper");
        let file = nested.join("bindizr.db");

        create_parent_dir(file.to_str().expect("utf-8")).expect("creates the directory");

        assert!(nested.is_dir());

        // The database holds TSIG secrets, so the directory gates access.
        let mode = fs::metadata(&nested)
            .expect("metadata")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o700, "mode was {mode:o}");

        // Already there on the next start, which must not be an error.
        create_parent_dir(file.to_str().expect("utf-8")).expect("accepts an existing directory");

        // These name no directory to create.
        create_parent_dir("bindizr.db").expect("bare filename");
        create_parent_dir("file::memory:?cache=shared").expect("in-memory URI");
        create_parent_dir("sqlite:my_database.db").expect("sqlite URI");
    }

    /// Verify that a path without the `sqlite:` scheme gains it, and one with
    /// it passes through.
    #[test]
    fn to_url_prefixes_paths_without_the_sqlite_scheme() {
        assert_eq!(
            to_url("/absolute/path/to/database.db").unwrap(),
            "sqlite:/absolute/path/to/database.db"
        );
        assert_eq!(
            to_url("relative/path/to/database.db").unwrap(),
            "sqlite:relative/path/to/database.db"
        );
        assert_eq!(
            to_url("file::memory:?cache=shared").unwrap(),
            "sqlite:file::memory:?cache=shared"
        );
        assert_eq!(
            to_url("sqlite:my_database.db").unwrap(),
            "sqlite:my_database.db"
        );
    }

    /// Verify that an empty path is rejected rather than turned into a URL.
    #[test]
    fn to_url_rejects_an_empty_path() {
        assert!(matches!(to_url(""), Err(DatabaseError::EmptySqlitePath)));
    }
}
