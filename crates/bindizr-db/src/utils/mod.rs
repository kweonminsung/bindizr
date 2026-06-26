pub(super) fn to_sqlite_url(file_path: &str) -> Result<String, String> {
    if file_path.trim().is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    // Keep existing sqlite URL
    if file_path.starts_with("sqlite:") {
        return Ok(file_path.to_string());
    }

    Ok(format!("sqlite:{}", file_path))
}

#[cfg(test)]
mod tests;
