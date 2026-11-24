use std::fmt;

use bindizr_core::outln;
use bindizr_service::types::{
    CreateTsigKeyRequest, MessageResponse, PaginatedResponse, SingleTsigKeyResponse, TsigKeyFilter,
    TsigKeyResponse,
};
use clap::Subcommand;

use crate::cli::error::CliError;
use crate::cli::output;
use crate::cli::output::{OutputFormat, TsigKeyRow};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for managing TSIG update and transfer credentials.
#[derive(Clone, PartialEq, Eq, Subcommand)]
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
        /// HMAC algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512, hmac-sha1 (legacy)
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Existing base64 secret to import (omit to generate a random one)
        #[arg(long, value_name = "BASE64")]
        secret: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List TSIG keys, every one or one role's (secrets are not shown; use `get`)
    #[command(alias = "ls")]
    List {
        /// Only the TSIG keys authenticating into this role
        #[arg(long, value_name = "ROLE_NAME")]
        role: Option<String>,
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

impl fmt::Debug for TsigKeyCommand {
    /// Format the command while masking any imported TSIG secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create {
                name,
                role,
                algorithm,
                secret: _,
                output,
            } => f
                .debug_struct("Create")
                .field("name", name)
                .field("role", role)
                .field("algorithm", algorithm)
                .field("secret", &"<redacted>")
                .field("output", output)
                .finish(),
            Self::List {
                role,
                limit,
                offset,
                output,
            } => f
                .debug_struct("List")
                .field("role", role)
                .field("limit", limit)
                .field("offset", offset)
                .field("output", output)
                .finish(),
            Self::Get { name, output } => f
                .debug_struct("Get")
                .field("name", name)
                .field("output", output)
                .finish(),
            Self::Export { name } => f.debug_struct("Export").field("name", name).finish(),
            Self::Delete { name, output } => f
                .debug_struct("Delete")
                .field("name", name)
                .field("output", output)
                .finish(),
        }
    }
}

/// Handle the `tsig-key` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TsigKeyCommand) -> Result<(), CliError> {
    match subcommand {
        TsigKeyCommand::Create {
            name,
            role,
            algorithm,
            secret,
            output,
        } => {
            let response = client::send_command::<SingleTsigKeyResponse>(
                DaemonCommand::CreateTsigKey(CreateTsigKeyRequest {
                    name,
                    algorithm,
                    secret,
                    role_name: role,
                }),
            )
            .await?;
            output::print_response(&response.data, output, |response| {
                vec![TsigKeyRow::from(response)]
            })?;
        }
        TsigKeyCommand::List {
            role,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<TsigKeyResponse>>(
                DaemonCommand::ListTsigKeys(TsigKeyFilter {
                    role_name: role,
                    limit,
                    offset,
                }),
            )
            .await?;
            output::print_page(&response.data, output, |tsig_key| {
                TsigKeyRow::from(tsig_key)
            })?;
        }
        TsigKeyCommand::Get { name, output } => {
            let response =
                client::send_command::<SingleTsigKeyResponse>(DaemonCommand::GetTsigKey { name })
                    .await?;
            output::print_response(&response.data, output, |response| {
                vec![TsigKeyRow::from(response)]
            })?;
        }
        TsigKeyCommand::Export { name } => {
            let response =
                client::send_command::<SingleTsigKeyResponse>(DaemonCommand::GetTsigKey { name })
                    .await?;
            print_bind_key(&response.data);
        }
        TsigKeyCommand::Delete { name, output } => {
            let response =
                client::send_command::<MessageResponse>(DaemonCommand::DeleteTsigKey { name })
                    .await?;

            if output == OutputFormat::Table {
                outln!("{}", response.message);
            } else {
                output::print_payload(&response.data, output)?;
            }
        }
    }

    Ok(())
}

/// Print the `key` statement BIND, Knot and NSD all read a TSIG key from, so
/// the secret reaches a secondary as something to paste rather than reformat.
fn print_bind_key(response: &SingleTsigKeyResponse) {
    outln!("key \"{}\" {{", response.tsig_key.name);
    outln!("    algorithm {};", response.tsig_key.algorithm);
    outln!("    secret \"{}\";", response.secret);
    outln!("}};");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Command;

    /// Verify that Debug masks a secret supplied on the command line.
    #[test]
    fn tsig_create_command_debug_masks_secret() {
        let subcommand = TsigKeyCommand::Create {
            name: "test".to_string(),
            role: "admin".to_string(),
            algorithm: None,
            secret: Some("fixture-tsig-key".to_string()),
            output: OutputFormat::Table,
        };
        let direct = format!("{subcommand:?}");
        let nested = format!("{:#?}", Command::TsigKey { subcommand });

        for debug in [direct, nested] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("fixture-tsig-key"));
        }
    }
}
