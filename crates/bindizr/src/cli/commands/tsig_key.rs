use bindizr_core::log_debug;
use bindizr_service::types::{
    CreateTsigGrantRequest, CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse,
};
use clap::{ArgGroup, Subcommand};

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TsigGrantRow, TsigKeyRow, parse_response, print_response},
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            CreateTsigGrantParams, DaemonCommandKind, DeleteTsigGrantParams, TsigKeyNameParams,
            ZoneNameParams,
        },
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
        /// types) without any grant. Effectively write access to all DNS
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
    /// Delete a TSIG key (refused while it still holds grants)
    #[command(alias = "rm")]
    Delete {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
    },
    /// Grant a TSIG key nsupdate rights in a zone
    Grant {
        /// Name of an existing non-global key (global keys already cover every zone)
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Name of the zone
        #[arg(value_name = "ZONE_NAME")]
        zone: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT' (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List a key's grants, or every grant that applies to a zone
    #[command(group(ArgGroup::new("scope").required(true).args(["name", "zone"])))]
    Grants {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: Option<String>,
        /// List the grants that apply to this zone instead
        #[arg(long, value_name = "ZONE_NAME")]
        zone: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Revoke one of a key's grants by grant ID
    Revoke {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// ID of the grant to revoke (see `tsig-key grants`)
        #[arg(value_name = "GRANT_ID")]
        id: i32,
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
                eprintln!("Warning: this key can update every zone without any grant.");
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
        TsigKeyCommand::Grant {
            name,
            zone,
            pattern,
            types,
            output,
        } => {
            let res = client
                .send_command(
                    DaemonCommandKind::TsigGrantCreate,
                    CreateTsigGrantParams {
                        key_name: name,
                        request: CreateTsigGrantRequest {
                            zone_name: zone,
                            record_name_pattern: pattern,
                            record_types: types,
                        },
                    },
                )
                .await?;
            print_response(&res.data, output, |grant: &GetTsigGrantResponse| {
                vec![TsigGrantRow::from(grant)]
            })?;
        }
        TsigKeyCommand::Grants { name, zone, output } => {
            let res = if let Some(zone) = zone {
                client
                    .send_command(
                        DaemonCommandKind::TsigGrantListByZone,
                        ZoneNameParams { name: zone },
                    )
                    .await?
            } else {
                // The `scope` group makes one of the two arguments mandatory.
                let name = name.unwrap_or_default();
                client
                    .send_command(
                        DaemonCommandKind::TsigGrantListByKey,
                        TsigKeyNameParams { name },
                    )
                    .await?
            };
            print_response(&res.data, output, |grants: &Vec<GetTsigGrantResponse>| {
                grants.iter().map(TsigGrantRow::from).collect()
            })?;
        }
        TsigKeyCommand::Revoke { name, id } => {
            let res = client
                .send_command(
                    DaemonCommandKind::TsigGrantDelete,
                    DeleteTsigGrantParams { key_name: name, id },
                )
                .await?;
            println!("{}", res.message);
        }
    }

    Ok(())
}
