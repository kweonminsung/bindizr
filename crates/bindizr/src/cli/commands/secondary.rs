use bindizr_core::outln;
use bindizr_service::types::{
    CreateSecondaryRequest, GetSecondaryResponse, PageFilter, PaginatedResponse, SecondaryResponse,
    UpdateSecondaryRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, SecondaryRow, print_payload, print_response},
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

/// Print one secondary in the requested format.
fn print_secondary(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |response: &SecondaryResponse| {
        vec![SecondaryRow::from(&response.secondary)]
    })
}
