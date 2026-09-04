//! The `token-policy` subcommands.

use bindizr_service::types::{CreateZoneTokenPolicyRequest, GetZoneTokenPolicyResponse};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{ZoneTokenPolicyRow, parse_response, print_table},
    },
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
pub(crate) enum TokenPolicyCommand {
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
    #[command(alias = "rm")]
    Remove {
        /// The name of the zone
        name: String,
        /// ID of the policy to remove (see `token-policy list`)
        id: i32,
    },
}

pub(crate) async fn handle_command(subcommand: TokenPolicyCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    match subcommand {
        TokenPolicyCommand::Add {
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
        TokenPolicyCommand::List { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTokenPolicyList,
                    ZonePolicyListParams { zone_name: name },
                )
                .await?;
            let policies: Vec<GetZoneTokenPolicyResponse> = parse_response(&response.data)?;
            print_table(policies.iter().map(ZoneTokenPolicyRow::from).collect());
        }
        TokenPolicyCommand::Remove { name, id } => {
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
