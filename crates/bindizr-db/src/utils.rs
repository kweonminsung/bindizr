use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// Create the directory a SQLite path names, since SQLite itself fails with
/// a bare "unable to open database file". A path naming no directory, and the
/// URI forms (`sqlite:`, `file:`), are left alone.
///
/// What this creates is 0700, like the daemon's socket directory: the database
/// holds TSIG secrets. A directory that already exists is the operator's.
pub(crate) fn create_parent_dir(file_path: &str) -> Result<(), String> {
    let file_path = file_path.trim();
    if file_path.starts_with("sqlite:") || file_path.starts_with("file:") {
        return Ok(());
    }
    let Some(parent) = Path::new(file_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.is_dir() {
        return Ok(());
    }

    let failed = |e: std::io::Error| {
        format!(
            "Failed to create the SQLite directory '{}' (check database.sqlite.file_path): {}",
            parent.display(),
            e
        )
    };
    fs::create_dir_all(parent).map_err(failed)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(failed)
}

/// Convert a configured SQLite path into a SQLx connection URL.
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

    /// Verify that the SQLite directory is created only where the path names one.
    #[test]
    fn create_parent_dir_makes_the_directory_a_path_names() {
        let temp = tempfile::tempdir().expect("temp dir");
        let nested = temp.path().join("state").join("deeper");
        let file = nested.join("bindizr.db");

        create_parent_dir(file.to_str().expect("utf-8")).expect("creates the directory");
        assert!(nested.is_dir());
        // The database holds TSIG secrets, so the directory gates access.
        let mode = std::fs::metadata(&nested)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {:o}", mode);
        // Already there on the next start, which must not be an error.
        create_parent_dir(file.to_str().expect("utf-8")).expect("accepts an existing directory");

        // These name no directory to create.
        create_parent_dir("bindizr.db").expect("bare filename");
        create_parent_dir("file::memory:?cache=shared").expect("in-memory URI");
        create_parent_dir("sqlite:my_database.db").expect("sqlite URI");
    }

    /// Verify that to sqlite url formats plain paths.
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
