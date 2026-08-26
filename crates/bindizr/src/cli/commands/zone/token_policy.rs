//! The `zone token-policy` subcommands.

use bindizr_service::types::{CreateZoneTokenPolicyRequest, GetZoneTokenPolicyResponse};
use clap::Subcommand;

use crate::{
    cli::{error::CliError, output::parse_response},
    socket::{
        client::DaemonSocketClient,
        types::{
            AddZoneTokenPolicyParams, DaemonCommandKind, RemoveZonePolicyParams,
            ZonePolicyListParams,
        },
    },
};

/// Subcommands for managing a zone's API token policies.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneTokenPolicyCommand {
    /// Grant an API token record rights in a zone
    Add {
        /// The name of the zone
        name: String,
        /// Name of an existing non-global API token (global tokens already cover every zone)
        #[arg(long, value_name = "NAME")]
        token: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT' (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
    },
    /// List a zone's token policies
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        name: String,
    },
    /// Remove a token policy from a zone by policy ID
    Remove {
        /// The name of the zone
        name: String,
        /// ID of the policy to remove (see `zone token-policy list`)
        id: i32,
    },
}

pub(crate) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneTokenPolicyCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneTokenPolicyCommand::Add {
            name,
            token,
            pattern,
            types,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTokenPolicyAdd,
                    AddZoneTokenPolicyParams {
                        zone_name: name,
                        request: CreateZoneTokenPolicyRequest {
                            api_token: token,
                            record_name_pattern: pattern,
                            record_types: types,
                        },
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneTokenPolicyCommand::List { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTokenPolicyList,
                    ZonePolicyListParams { zone_name: name },
                )
                .await?;
            print_token_policies(&response.data)?;
        }
        ZoneTokenPolicyCommand::Remove { name, id } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTokenPolicyRemove,
                    RemoveZonePolicyParams {
                        zone_name: name,
                        id,
                    },
                )
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}

fn print_token_policies(data: &serde_json::Value) -> Result<(), String> {
    let policies: Vec<GetZoneTokenPolicyResponse> = parse_response(data)?;

    if policies.is_empty() {
        println!("No token policies found");
        return Ok(());
    }

    println!("Token Policies:");
    println!(
        "{:<5} {:<25} {:<20} {:<20}",
        "ID", "TOKEN", "NAME PATTERN", "RECORD TYPES"
    );
    println!("{}", "-".repeat(75));

    for policy in policies {
        println!(
            "{:<5} {:<25} {:<20} {:<20}",
            policy.id, policy.api_token, policy.record_name_pattern, policy.record_types
        );
    }

    Ok(())
}
