use bindizr_core::dns::Serial;
use bindizr_core::outln;
use bindizr_service::types::{
    CheckSecondaryResponse, CreateSecondaryRequest, MessageResponse, PageRequest,
    PaginatedResponse, SecondaryResponse, SecondaryStatus, SecondaryTransferFilter,
    SecondaryTransfersResponse, SingleSecondaryResponse, UpdateSecondaryRequest,
};
use chrono::{DateTime, Utc};
use clap::Subcommand;

use crate::cli::error::CliError;
use crate::cli::output::{OutputFormat, RenderOutputError, SecondaryRow, TransferRow};
use crate::cli::{output, time};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for managing the secondary servers.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
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
    /// The transfers Bindizr served a secondary, newest first: AXFR, IXFR as a delta or the whole zone, refused, or failed
    Transfers {
        /// Name of the secondary
        #[arg(value_name = "NAME")]
        name: String,
        /// At most this many transfers (1000 when omitted)
        #[arg(long)]
        limit: Option<u32>,
        /// Only the transfers of this zone
        #[arg(long, value_name = "ZONE")]
        zone: Option<String>,
        /// Only transfers at or after this time: a span ago (7d, 12h, 30m), a
        /// UTC date (2026-10-01), or RFC 3339
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only transfers before this time, in the same forms
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        until: Option<DateTime<Utc>>,
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
            let response = client::send_command::<SingleSecondaryResponse>(
                DaemonCommand::CreateSecondary(CreateSecondaryRequest {
                    name,
                    address,
                    notify_key_name: notify_key,
                }),
            )
            .await?;
            log::debug!("Secondary creation result: {response:?}");
            print_secondary(&response.data, output)?;
        }
        SecondaryCommand::List {
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<SecondaryResponse>>(
                DaemonCommand::ListSecondaries(PageRequest { limit, offset }),
            )
            .await?;
            log::debug!("Secondary list result: {response:?}");
            output::print_page(&response.data, output, |secondary| {
                SecondaryRow::from(secondary)
            })?;
        }
        SecondaryCommand::Get { name, output } => {
            let response =
                client::send_command::<SingleSecondaryResponse>(DaemonCommand::GetSecondary {
                    name,
                })
                .await?;
            log::debug!("Secondary get result: {response:?}");
            print_secondary(&response.data, output)?;
        }
        SecondaryCommand::Update {
            name,
            address,
            enabled,
            notify_key,
            output,
        } => {
            let response =
                client::send_command::<SingleSecondaryResponse>(DaemonCommand::UpdateSecondary {
                    name,
                    request: UpdateSecondaryRequest {
                        address,
                        enabled,
                        notify_key_name: notify_key,
                    },
                })
                .await?;
            log::debug!("Secondary update result: {response:?}");
            print_secondary(&response.data, output)?;
        }
        SecondaryCommand::Check { name, output } => {
            let response =
                client::send_command::<CheckSecondaryResponse>(DaemonCommand::CheckSecondary {
                    name: name.clone(),
                })
                .await?;
            log::debug!("Secondary check result: {response:?}");
            let check = &response.data;

            if output == OutputFormat::Table {
                print_check(check);
            } else {
                output::print_payload(check, output)?;
            }

            // A failed part exits non-zero, so a script can branch on it.
            if !check.is_healthy() {
                return Err(CliError::request(format!(
                    "secondary '{name}' failed the check"
                )));
            }
        }
        SecondaryCommand::Transfers {
            name,
            limit,
            zone,
            since,
            until,
            output,
        } => {
            let response = client::send_command::<SecondaryTransfersResponse>(
                DaemonCommand::ListSecondaryTransfers {
                    name,
                    filter: SecondaryTransferFilter {
                        limit,
                        zone_name: zone,
                        since,
                        until,
                    },
                },
            )
            .await?;
            log::debug!("Secondary transfers result: {response:?}");
            let transfers = &response.data;

            if output == OutputFormat::Table {
                output::print_table(transfers.transfers.iter().map(TransferRow::from).collect());
                outln!("{}", output::display_transfer_summary(&transfers.summary));
            } else {
                output::print_payload(transfers, output)?;
            }
        }
        SecondaryCommand::Delete { name, output } => {
            let response =
                client::send_command::<MessageResponse>(DaemonCommand::DeleteSecondary { name })
                    .await?;
            log::debug!("Secondary deletion result: {response:?}");

            if output == OutputFormat::Table {
                outln!("{}", response.message);
            } else {
                output::print_payload(&response.data, output)?;
            }
        }
    }

    Ok(())
}

/// Print a check as one line per part, the way `doctor` reports.
fn print_check(check: &CheckSecondaryResponse) {
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
        match &secondary.notify_key_name {
            Some(key) => format!(", NOTIFY signed with {key}"),
            None => String::new(),
        }
    );

    match &check.resolve_error {
        Some(error) => outln!("Resolution failed: {error}"),
        None => outln!("Resolves to: {}", check.addresses.join(", ")),
    }

    if let Some(error) = &check.listener_error {
        outln!("Bindizr's own listener did not answer: {error}");
    }

    let catalog = &check.catalog;

    match (catalog.visible_serial, catalog.status) {
        (Some(serial), SecondaryStatus::InSync | SecondaryStatus::Reachable) => outln!(
            "Catalog zone {}: {} at serial {serial}",
            check.catalog_zone_name,
            catalog.status
        ),
        (Some(serial), status) => outln!(
            "Catalog zone {}: {status} at serial {serial} (bindizr serves {})",
            check.catalog_zone_name,
            check.catalog_serial.map_or(0, Serial::as_u32)
        ),
        (None, status) => outln!(
            "Catalog zone {}: {status} ({})",
            check.catalog_zone_name,
            catalog.error.as_deref().unwrap_or("unknown error")
        ),
    }

    for notify in &check.notifies {
        match &notify.error {
            Some(error) => outln!("NOTIFY to {}: rejected ({error})", notify.address),
            None => outln!("NOTIFY to {}: accepted", notify.address),
        }
    }

    outln!(
        "Transfers: {}",
        output::display_transfer_summary(&check.transfers)
    );
}

/// Print one secondary in the requested format.
fn print_secondary(
    response: &SingleSecondaryResponse,
    output: OutputFormat,
) -> Result<(), RenderOutputError> {
    output::print_response(response, output, |response| {
        vec![SecondaryRow::from(&response.secondary)]
    })
}
