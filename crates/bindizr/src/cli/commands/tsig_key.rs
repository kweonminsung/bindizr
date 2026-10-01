use bindizr_core::outln;
use bindizr_service::types::{
    CreateTsigKeyRequest, GetTsigKeyResponse, MessageResponse, PageRequest, PaginatedResponse,
    TsigKeyResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TsigKeyRow, print_page, print_payload, print_response},
    },
    socket::{client, types::DaemonCommand},
};

/// Subcommands for managing TSIG update and transfer credentials.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub(crate) enum TsigKeyCommand {
    /// Create a TSIG key in a role (generates a secret unless one is provided)
    #[command(after_help = "\
Examples:
  bindizr tsig-key create update-key --role rfc2136-legacy
  bindizr tsig-key create xfer-key --role secondaries --algorithm hmac-sha512")]
    Create {
        /// Key name; appears on the wire in the TSIG record (e.g. "update-key")
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Role whose grants decide what the key may sign (see `role grant`)
        #[arg(long, value_name = "ROLE_NAME")]
        role: String,
        /// HMAC algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Existing base64 secret to import (omit to generate a random one)
        #[arg(long, value_name = "BASE64")]
        secret: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List all TSIG keys (secrets are not shown; use `get`)
    #[command(alias = "ls")]
    List {
        /// Maximum number of keys to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of keys to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show one TSIG key including its secret
    Get {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Print the key as a BIND `key` block, ready to paste into a
    /// secondary's named.conf — it carries the secret
    Export {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
    },
    /// Delete a TSIG key (refused while it still signs a secondary's NOTIFY)
    #[command(alias = "rm")]
    Delete {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `tsig-key` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TsigKeyCommand) -> Result<(), CliError> {
    match subcommand {
        TsigKeyCommand::Create {
            name,
            algorithm,
            secret,
            role,
            output,
        } => {
            let res = client::send_command::<TsigKeyResponse>(DaemonCommand::CreateTsigKey(
                CreateTsigKeyRequest {
                    name,
                    algorithm,
                    secret,
                    role_name: role,
                },
            ))
            .await?;
            log::debug!("TSIG key creation result: {:?}", res);
            print_response(&res.data, output, |key| vec![TsigKeyRow::from(key)])?;
        }
        TsigKeyCommand::List {
            limit,
            offset,
            output,
        } => {
            let res = client::send_command::<PaginatedResponse<GetTsigKeyResponse>>(
                DaemonCommand::ListTsigKeys(PageRequest { limit, offset }),
            )
            .await?;
            log::debug!("TSIG key list result: {:?}", res);
            print_page(&res.data, output, |item| TsigKeyRow::from(item))?;
        }
        TsigKeyCommand::Get { name, output } => {
            let res =
                client::send_command::<TsigKeyResponse>(DaemonCommand::GetTsigKey { name }).await?;
            log::debug!("TSIG key get result: {:?}", res);
            print_response(&res.data, output, |key| vec![TsigKeyRow::from(key)])?;
        }
        TsigKeyCommand::Export { name } => {
            let res =
                client::send_command::<TsigKeyResponse>(DaemonCommand::GetTsigKey { name }).await?;
            print_bind_key(&res.data);
        }
        TsigKeyCommand::Delete { name, output } => {
            let res =
                client::send_command::<MessageResponse>(DaemonCommand::DeleteTsigKey { name })
                    .await?;
            log::debug!("TSIG key deletion result: {:?}", res);
            match output {
                OutputFormat::Table => outln!("{}", res.message),
                _ => print_payload(&res.data, output)?,
            }
        }
    }
    Ok(())
}

/// The `key` statement BIND, Knot and NSD all read a TSIG key from, so the
/// secret reaches a secondary as something to paste rather than reformat.
fn print_bind_key(key: &TsigKeyResponse) {
    outln!("key \"{}\" {{", key.tsig_key.name);
    outln!("    algorithm {};", key.tsig_key.algorithm);
    outln!("    secret \"{}\";", key.secret);
    outln!("}};");
}
