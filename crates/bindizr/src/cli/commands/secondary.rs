use bindizr_core::outln;
use bindizr_service::types::{
    CreateSecondaryRequest, GetSecondaryResponse, PageFilter, PaginatedResponse,
    SecondaryCheckResponse, SecondaryResponse, UpdateSecondaryRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, SecondaryRow, parse_response, print_payload, print_response},
    },
    socket::{
        client,
        types::{DaemonCommandKind, SecondaryNameParams, UpdateSecondaryParams},
    },
};

/// Subcommands for managing the secondary servers.
#[derive(Subcommand, Debug)]
pub(crate) enum SecondaryCommand {
    /// Register a secondary: it receives NOTIFY and may pull zones unsigned
    /// from its address
    Create {
        /// Name of the secondary, a plain identifier (e.g. "ns2")
        #[arg(value_name = "NAME")]
        name: String,
        /// host[:port] (port 53 when left out); a hostname is resolved when used
        #[arg(long, value_name = "HOST[:PORT]")]
        address: String,
        /// TSIG key to sign NOTIFY to this server with (unsigned when omitted)
        #[arg(long, value_name = "KEY_NAME")]
        notify_key: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List all secondaries, disabled ones included
    #[command(alias = "ls")]
    List {
        /// Maximum number of secondaries to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of secondaries to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show one secondary
    Get {
        /// Name of the secondary
        #[arg(value_name = "NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Change a secondary's address, or enable or disable it
    Update {
        /// Name of the secondary
        #[arg(value_name = "NAME")]
        name: String,
        /// New host[:port]
        #[arg(long, value_name = "HOST[:PORT]")]
        address: Option<String>,
        /// Send it NOTIFY and admit its unsigned transfers, or stop without
        /// forgetting it
        #[arg(long, value_name = "true|false")]
        enabled: Option<bool>,
        /// TSIG key to sign NOTIFY with; "" sends it unsigned again
        #[arg(long, value_name = "KEY_NAME")]
        notify_key: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Check a secondary: where its address resolves, the catalog zone serial
    /// it serves against Bindizr's, and whether it accepts a NOTIFY
    Check {
        /// Name of the secondary
        #[arg(value_name = "NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Delete a secondary
    #[command(alias = "rm")]
    Delete {
        /// Name of the secondary
        #[arg(value_name = "NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `secondary` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: SecondaryCommand) -> Result<(), CliError> {
    match subcommand {
        SecondaryCommand::Create {
            name,
            address,
            notify_key,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateSecondary,
                CreateSecondaryRequest {
                    name,
                    address,
                    notify_key,
                },
            )
            .await?;

            log::debug!("Secondary creation result: {:?}", res);

            print_secondary(&res.data, output)?;
        }
        SecondaryCommand::List {
            limit,
            offset,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::ListSecondaries,
                PageFilter { limit, offset },
            )
            .await?;

            log::debug!("Secondary list result: {:?}", res);

            print_response(
                &res.data,
                output,
                |secondaries: &PaginatedResponse<GetSecondaryResponse>| {
                    secondaries.items.iter().map(SecondaryRow::from).collect()
                },
            )?;
        }
        SecondaryCommand::Get { name, output } => {
            let res = client::send_command(
                DaemonCommandKind::GetSecondary,
                SecondaryNameParams { name },
            )
            .await?;

            log::debug!("Secondary get result: {:?}", res);

            print_secondary(&res.data, output)?;
        }
        SecondaryCommand::Update {
            name,
            address,
            enabled,
            notify_key,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::UpdateSecondary,
                UpdateSecondaryParams {
                    name,
                    request: UpdateSecondaryRequest {
                        address,
                        enabled,
                        notify_key,
                    },
                },
            )
            .await?;

            log::debug!("Secondary update result: {:?}", res);

            print_secondary(&res.data, output)?;
        }
        SecondaryCommand::Check { name, output } => {
            let res = client::send_command(
                DaemonCommandKind::CheckSecondary,
                SecondaryNameParams { name: name.clone() },
            )
            .await?;

            log::debug!("Secondary check result: {:?}", res);

            let check: SecondaryCheckResponse = parse_response(&res.data)?;
            match output {
                OutputFormat::Table => print_check(&check),
                _ => print_payload(&res.data, output)?,
            }
            // A failed part exits non-zero, so a script can branch on it.
            if !check.is_healthy() {
                return Err(CliError::from(format!(
                    "Secondary '{}' failed the check",
                    name
                )));
            }
        }
        SecondaryCommand::Delete { name, output } => {
            let res = client::send_command(
                DaemonCommandKind::DeleteSecondary,
                SecondaryNameParams { name },
            )
            .await?;

            log::debug!("Secondary deletion result: {:?}", res);

            match output {
                OutputFormat::Table => outln!("{}", res.message),

                _ => print_payload(&res.data, output)?,
            }
        }
    }

    Ok(())
}

/// Print a check as one line per part, the way `doctor` reports.
fn print_check(check: &SecondaryCheckResponse) {
    let secondary = &check.secondary;
    outln!(
        "Secondary {}: {} ({}{})",
        secondary.name,
        secondary.address,
        if secondary.enabled {
            "enabled"
        } else {
            "disabled"
        },
        match &secondary.notify_key {
            Some(key) => format!(", NOTIFY signed with {}", key),
            None => String::new(),
        }
    );
    match &check.resolve_error {
        Some(error) => outln!("Resolution failed: {}", error),
        None => outln!("Resolves to: {}", check.addresses.join(", ")),
    }
    if let Some(error) = &check.listener_error {
        outln!("Bindizr's own listener did not answer: {}", error);
    }
    let catalog = &check.catalog;
    match (catalog.visible_serial, catalog.status.as_str()) {
        (Some(serial), "in_sync") => outln!(
            "Catalog zone {}: in sync at serial {}",
            check.catalog_zone,
            serial
        ),
        (Some(serial), "reachable") => outln!(
            "Catalog zone {}: reachable at serial {}",
            check.catalog_zone,
            serial
        ),
        (Some(serial), status) => outln!(
            "Catalog zone {}: {} at serial {} (bindizr serves {})",
            check.catalog_zone,
            status,
            serial,
            check.catalog_serial.unwrap_or_default()
        ),
        (None, _) => outln!(
            "Catalog zone {}: unreachable ({})",
            check.catalog_zone,
            catalog.error.as_deref().unwrap_or("unknown error")
        ),
    }
    for notify in &check.notifies {
        match &notify.error {
            None => outln!("NOTIFY to {}: accepted", notify.address),
            Some(error) => outln!("NOTIFY to {}: rejected ({})", notify.address, error),
        }
    }
}

/// Print one secondary in the requested format.
fn print_secondary(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |response: &SecondaryResponse| {
        vec![SecondaryRow::from(&response.secondary)]
    })
}
