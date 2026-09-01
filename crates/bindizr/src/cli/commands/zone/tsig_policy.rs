//! The `zone tsig-policy` subcommands.

use bindizr_service::types::{CreateZoneTsigPolicyRequest, GetZoneTsigPolicyResponse};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{ZoneTsigPolicyRow, parse_response, print_table},
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            AddZoneTsigPolicyParams, DaemonCommandKind, RemoveZonePolicyParams,
            ZonePolicyListParams,
        },
    },
};

/// Subcommands for managing a zone's TSIG policies.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneTsigPolicyCommand {
    /// Grant a TSIG key nsupdate rights in a zone
    Add {
        /// The name of the zone
        name: String,
        /// Name of an existing non-global TSIG key (global keys already cover
        /// every zone)
        #[arg(long)]
        key: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact
        /// relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT'
        /// (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
    },
    /// List a zone's TSIG policies
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        name: String,
    },
    /// Remove a TSIG policy from a zone by policy ID
    #[command(alias = "rm")]
    Remove {
        /// The name of the zone
        name: String,
        /// ID of the policy to remove (see `zone tsig-policy list`)
        id: i32,
    },
}

pub(crate) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneTsigPolicyCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneTsigPolicyCommand::Add {
            name,
            key,
            pattern,
            types,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTsigPolicyAdd,
                    AddZoneTsigPolicyParams {
                        zone_name: name,
                        request: CreateZoneTsigPolicyRequest {
                            tsig_key: key,
                            record_name_pattern: pattern,
                            record_types: types,
                        },
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneTsigPolicyCommand::List { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTsigPolicyList,
                    ZonePolicyListParams { zone_name: name },
                )
                .await?;
            print_tsig_policies(&response.data)?;
        }
        ZoneTsigPolicyCommand::Remove { name, id } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTsigPolicyRemove,
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

fn print_tsig_policies(data: &serde_json::Value) -> Result<(), String> {
    let policies: Vec<GetZoneTsigPolicyResponse> = parse_response(data)?;

    print_table(policies.iter().map(ZoneTsigPolicyRow::from).collect());

    Ok(())
}
