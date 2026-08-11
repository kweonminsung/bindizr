use bindizr_service::types::PaginatedResponse;
use serde::{Deserialize, de::DeserializeOwned};
use tabled::{Table, Tabled, settings::Style};

/// Output format for CLI results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Json,
    Yaml,
    Table,
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

/// Read a daemon response payload as the type the command expects.
pub(crate) fn parse_response<T: DeserializeOwned>(data: &serde_json::Value) -> Result<T, String> {
    serde_json::from_value(data.clone()).map_err(|e| format!("Unexpected daemon response: {}", e))
}

/// A listing answers with a page; `get` and `update` answer with the item
/// alone. Both feed the same table.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum ItemOrPage<T> {
    Page(PaginatedResponse<T>),
    One(T),
}

impl<T> ItemOrPage<T> {
    pub(crate) fn items(&self) -> &[T] {
        match self {
            ItemOrPage::Page(page) => &page.items,
            ItemOrPage::One(item) => std::slice::from_ref(item),
        }
    }
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
        OutputFormat::Table => print_table(to_table_rows(&parse_response(data)?)),
    }
    Ok(())
}

/// Print table rows, or a placeholder when there are none.
pub(crate) fn print_table<U: Tabled>(rows: Vec<U>) {
    if rows.is_empty() {
        println!("No resources found.");
    } else {
        println!("{}", Table::new(rows).with(Style::blank()));
    }
}
