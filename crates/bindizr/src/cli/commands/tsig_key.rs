use bindizr_core::log_debug;
use bindizr_service::types::{CreateTsigKeyRequest, GetTsigKeyResponse};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TsigKeyRow, parse_response, print_response},
    },
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, TsigKeyNameParams},
    },
};

/// Subcommands for managing TSIG keys used for nsupdate authentication.
#[derive(Subcommand, Debug)]
pub(crate) enum TsigKeyCommand {
    /// Create a TSIG key (generates a secret unless one is provided)
    Create {
        /// Key name; appears on the wire in the TSIG record (e.g. "update-key")
        #[arg(long, value_name = "KEY_NAME")]
        name: String,
        /// HMAC algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Existing base64 secret to import (omit to generate a random one)
        #[arg(long, value_name = "BASE64")]
        secret: Option<String>,
        /// Make the key global: it may update EVERY zone (all names, all
        /// types) without any policy. Effectively write access to all DNS
        /// data — use sparingly. Fixed at creation.
        #[arg(long)]
        global: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List all TSIG keys (secrets are not shown; use `get`)
    #[command(alias = "ls")]
    List {
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show one TSIG key including its secret
    Get {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Delete a TSIG key (refused while zone TSIG policies still use it)
    #[command(alias = "rm")]
    Delete {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
    },
}

/// Handle the `tsig-key` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TsigKeyCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        TsigKeyCommand::Create {
            name,
            algorithm,
            secret,
            global,
            output,
        } => {
            let res = client
                .send_command(
                    DaemonCommandKind::TsigKeyCreate,
                    CreateTsigKeyRequest {
                        name,
                        algorithm,
                        secret,
                        global,
                    },
                )
                .await?;

            log_debug!("TSIG key creation result: {:?}", res);

            let key: GetTsigKeyResponse = parse_response(&res.data)?;
            // stderr, so `--output json` stays parseable.
            if key.global {
                eprintln!("Warning: this key can update every zone without any policy.");
            }
            print_response(&res.data, output, |key: &GetTsigKeyResponse| {
                vec![TsigKeyRow::from(key)]
            })?;
        }
        TsigKeyCommand::List { output } => {
            let res = client
                .send_command(DaemonCommandKind::TsigKeyList, ())
                .await?;

            log_debug!("TSIG key list result: {:?}", res);

            print_response(&res.data, output, |keys: &Vec<GetTsigKeyResponse>| {
                keys.iter().map(TsigKeyRow::from).collect()
            })?;
        }
        TsigKeyCommand::Get { name, output } => {
            let res = client
                .send_command(DaemonCommandKind::TsigKeyGet, TsigKeyNameParams { name })
                .await?;

            log_debug!("TSIG key get result: {:?}", res);

            print_response(&res.data, output, |key: &GetTsigKeyResponse| {
                vec![TsigKeyRow::from(key)]
            })?;
        }
        TsigKeyCommand::Delete { name } => {
            let res = client
                .send_command(DaemonCommandKind::TsigKeyDelete, TsigKeyNameParams { name })
                .await?;

            log_debug!("TSIG key deletion result: {:?}", res);

            println!("{}", res.message);
        }
    }

    Ok(())
}
