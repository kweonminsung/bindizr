pub(super) mod config;
pub(super) mod doctor;
pub(super) mod record;
pub(super) mod restart;
pub(super) mod start;
pub(super) mod status;
pub(super) mod stop;
pub(super) mod token;
pub(super) mod tsig_key;
pub(super) mod zone;

/// Read command input from a file path, or from stdin when the path is `-`.
pub(super) fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(|e| format!("Failed to read from stdin: {}", e))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read '{}': {}", path, e))
    }
}
