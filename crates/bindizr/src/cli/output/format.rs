use serde::Serialize;
use std::fmt;
use tabled::{Table, Tabled, settings::Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Json,
    Yaml,
    Table,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Table => write!(f, "table"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

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

/// Print output with table support
pub(crate) fn print_output_with_table<T, U>(
    data: &T,
    format: OutputFormat,
    to_table_rows: impl Fn(&T) -> Vec<U>,
) -> Result<(), String>
where
    T: Serialize,
    U: Tabled,
{
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(data)
                .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(data)
                .map_err(|e| format!("Failed to serialize to YAML: {}", e))?;
            println!("{}", yaml);
        }
        OutputFormat::Table => {
            let rows = to_table_rows(data);
            if rows.is_empty() {
                println!("No resources found.");
            } else {
                let table = Table::new(rows).with(Style::blank()).to_string();
                println!("{}", table);
            }
        }
    }
    Ok(())
}
