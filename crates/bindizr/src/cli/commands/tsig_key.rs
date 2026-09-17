use bindizr_core::{errln, outln};
use bindizr_service::types::{
    CreateTsigGrantRequest, CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse,
    PaginatedResponse, TsigGrantResponse, TsigKeyResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TsigGrantRow, TsigKeyRow, parse_response, print_response},
    },
    socket::{
        client,
        types::{
            CreateTsigGrantParams, DaemonCommandKind, DeleteTsigGrantParams, TsigKeyNameParams,
        },
    },
};

/// Subcommands for managing TSIG update and transfer credentials.
#[derive(Subcommand, Debug)]
pub(crate) enum TsigKeyCommand {
    /// Create a TSIG key (generates a secret unless one is provided)
    Create {
        /// Key name; appears on the wire in the TSIG record (e.g. "update-key")
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// HMAC algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Existing base64 secret to import (omit to generate a random one)
        #[arg(long, value_name = "BASE64")]
        secret: Option<String>,
        /// Allow updates and transfers for every zone without grants.
        /// Fixed at creation
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
    /// Print the key as a BIND `key` block, ready to paste into a
    /// secondary's named.conf — it carries the secret
    Export {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
    },
    /// Delete a TSIG key (refused while it still holds grants)
    #[command(alias = "rm")]
    Delete {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
    },
    /// Grant a TSIG key rights in a zone: nsupdate, and — over the whole
    /// zone — transfers
    #[command(after_help = "\
Examples:
  bindizr tsig-key grant update-key example.com
  bindizr tsig-key grant acme-key example.com --pattern '_acme-challenge.*' --types TXT
  bindizr tsig-key grant xfer-key example.com --read-only")]
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
        /// Grant transfers only; the key may pull the zone but not change it
        #[arg(long)]
        read_only: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List a key's grants (`zone tsig-grants` lists a zone's)
    Grants {
        /// Name of the key
        #[arg(value_name = "KEY_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Revoke one of a key's grants by grant ID
    Revoke {
        /// ID of the grant to revoke (see `tsig-key grants`)
        #[arg(value_name = "GRANT_ID")]
        id: i32,
    },
}

/// Handle the `tsig-key` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TsigKeyCommand) -> Result<(), CliError> {
    match subcommand {
        TsigKeyCommand::Create {
            name,
            algorithm,
            secret,
            global,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateTsigKey,
                CreateTsigKeyRequest {
                    name,
                    algorithm,
                    secret,
                    global,
                },
            )
            .await?;

            log::debug!("TSIG key creation result: {:?}", res);

            let created: TsigKeyResponse = parse_response(&res.data)?;
            // stderr, so `--output json` stays parseable.
            if created.tsig_key.global {
                errln!("Warning: this key can update every zone without any grant.");
            }
            print_response(&res.data, output, |key: &TsigKeyResponse| {
                vec![TsigKeyRow::from(key)]
            })?;
        }
        TsigKeyCommand::List { output } => {
            let res = client::send_command(DaemonCommandKind::ListTsigKeys, ()).await?;

            log::debug!("TSIG key list result: {:?}", res);

            print_response(
                &res.data,
                output,
                |keys: &PaginatedResponse<GetTsigKeyResponse>| {
                    keys.items.iter().map(TsigKeyRow::from).collect()
                },
            )?;
        }
        TsigKeyCommand::Get { name, output } => {
            let res =
                client::send_command(DaemonCommandKind::GetTsigKey, TsigKeyNameParams { name })
                    .await?;

            log::debug!("TSIG key get result: {:?}", res);

            print_response(&res.data, output, |key: &TsigKeyResponse| {
                vec![TsigKeyRow::from(key)]
            })?;
        }
        TsigKeyCommand::Export { name } => {
            let res =
                client::send_command(DaemonCommandKind::GetTsigKey, TsigKeyNameParams { name })
                    .await?;
            let key: TsigKeyResponse = parse_response(&res.data).map_err(CliError::from)?;
            print_bind_key(&key);
        }
        TsigKeyCommand::Delete { name } => {
            let res =
                client::send_command(DaemonCommandKind::DeleteTsigKey, TsigKeyNameParams { name })
                    .await?;

            log::debug!("TSIG key deletion result: {:?}", res);

            outln!("{}", res.message);
        }
        TsigKeyCommand::Grant {
            name,
            zone,
            pattern,
            types,
            read_only,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateTsigGrant,
                CreateTsigGrantParams {
                    key_name: name,
                    request: CreateTsigGrantRequest {
                        zone_name: zone,
                        record_name_pattern: pattern,
                        record_types: types,
                        can_write: !read_only,
                    },
                },
            )
            .await?;
            print_response(&res.data, output, |response: &TsigGrantResponse| {
                vec![TsigGrantRow::from(&response.tsig_grant)]
            })?;
        }
        TsigKeyCommand::Grants { name, output } => {
            let res = client::send_command(
                DaemonCommandKind::ListTsigGrants,
                TsigKeyNameParams { name },
            )
            .await?;
            print_response(
                &res.data,
                output,
                |grants: &PaginatedResponse<GetTsigGrantResponse>| {
                    grants.items.iter().map(TsigGrantRow::from).collect()
                },
            )?;
        }
        TsigKeyCommand::Revoke { id } => {
            let res = client::send_command(
                DaemonCommandKind::DeleteTsigGrant,
                DeleteTsigGrantParams { id },
            )
            .await?;
            outln!("{}", res.message);
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
