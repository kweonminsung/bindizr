use bindizr_core::outln;
use bindizr_service::types::PaginatedResponse;
use clap::ValueEnum;
use serde::Serialize;
use tabled::{Table, Tabled, settings::Style};
use thiserror::Error;

/// Why a daemon response could not be rendered.
#[derive(Debug, Error)]
pub(crate) enum RenderOutputError {
    #[error("failed to serialize to YAML: {0}")]
    Yaml(#[source] serde_norway::Error),
    #[error("failed to serialize to JSON: {0}")]
    Json(#[source] serde_json::Error),
}

/// How a command renders its result. Deriving `ValueEnum` is what puts the
/// values in `--help` and in the generated shell completions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Yaml,
    Table,
}

/// Print a daemon response: the payload as JSON or YAML, or a table built
/// from it.
pub(crate) fn print_response<T, U>(
    data: &T,
    format: OutputFormat,
    to_table_rows: impl Fn(&T) -> Vec<U>,
) -> Result<(), RenderOutputError>
where
    T: Serialize,
    U: Tabled,
{
    match format {
        OutputFormat::Table => print_table(to_table_rows(data)),
        _ => print_payload(data, format)?,
    }
    Ok(())
}

/// Print one page of a listing as JSON or YAML, or as a table with a row
/// per item plus the count it left out, so a page is not mistaken for the
/// whole listing.
pub(crate) fn print_page<T, U>(
    page: &PaginatedResponse<T>,
    format: OutputFormat,
    to_table_row: impl Fn(&T) -> U,
) -> Result<(), RenderOutputError>
where
    T: Serialize,
    U: Tabled,
{
    if format != OutputFormat::Table {
        return print_payload(page, format);
    }
    print_table(page.items.iter().map(to_table_row).collect());
    let seen = page.pagination.offset + page.items.len() as u64;
    if seen < page.pagination.total {
        outln!(
            "Showing {} of {}; page the rest with --limit and --offset.",
            seen,
            page.pagination.total
        );
    }
    Ok(())
}

/// Print the payload as JSON or YAML, for a command that renders its own table.
pub(crate) fn print_payload<T: Serialize>(
    data: &T,
    format: OutputFormat,
) -> Result<(), RenderOutputError> {
    let rendered = match format {
        OutputFormat::Yaml => serde_norway::to_string(data).map_err(RenderOutputError::Yaml)?,
        OutputFormat::Json | OutputFormat::Table => {
            serde_json::to_string_pretty(data).map_err(RenderOutputError::Json)?
        }
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
