use bindizr_core::outln;
use serde::de::DeserializeOwned;
use tabled::{Table, Tabled, settings::Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Json,
    Yaml,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    /// Parse an output format from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "yaml" => Ok(OutputFormat::Yaml),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!(
                "Invalid output format: {}. Valid options are: json, yaml, table",
                s
            )),
        }
    }
}

/// Read a daemon response payload as the type the command expects.
pub(crate) fn parse_response<T: DeserializeOwned>(data: &serde_json::Value) -> Result<T, String> {
    serde_json::from_value(data.clone()).map_err(|e| format!("Unexpected daemon response: {}", e))
}

/// Print a daemon response: the payload verbatim for JSON and YAML, or a table
/// built from its typed form. Only the table path deserializes, so
/// `--output json` stays what the daemon sent.
pub(crate) fn print_response<T, U>(
    data: &serde_json::Value,
    format: OutputFormat,
    to_table_rows: impl Fn(&T) -> Vec<U>,
) -> Result<(), String>
where
    T: DeserializeOwned,
    U: Tabled,
{
    match format {
        OutputFormat::Table => {
            print_table(to_table_rows(&parse_response(data)?));
            print_page_remainder(data);
        }
        _ => print_payload(data, format)?,
    }
    Ok(())
}

/// Print the number of omitted rows so a table page is not mistaken for the complete listing.
fn print_page_remainder(data: &serde_json::Value) {
    let (Some(total), Some(shown)) = (
        data["pagination"]["total"].as_u64(),
        data["items"].as_array().map(|items| items.len() as u64),
    ) else {
        return;
    };

    let seen = data["pagination"]["offset"].as_u64().unwrap_or(0) + shown;
    if seen < total {
        outln!(
            "Showing {} of {}; page the rest with --limit and --offset.",
            seen,
            total
        );
    }
}

/// Print the payload as JSON or YAML, for a command that renders its own table.
pub(crate) fn print_payload(data: &serde_json::Value, format: OutputFormat) -> Result<(), String> {
    let rendered = match format {
        OutputFormat::Yaml => serde_norway::to_string(data)
            .map_err(|e| format!("Failed to serialize to YAML: {}", e))?,
        OutputFormat::Json | OutputFormat::Table => serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))?,
    };
    outln!("{}", rendered);
    Ok(())
}

/// Print table rows, or a placeholder when there are none.
pub(crate) fn print_table<U: Tabled>(rows: Vec<U>) {
    if rows.is_empty() {
        outln!("No resources found.");
    } else {
        outln!("{}", Table::new(rows).with(Style::blank()));
    }
}
