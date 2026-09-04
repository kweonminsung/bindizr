//! The `tsig-policy` subcommands.

use bindizr_service::types::{CreateZoneTsigPolicyRequest, GetZoneTsigPolicyResponse};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, ZoneTsigPolicyRow, print_response},
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
pub(crate) enum TsigPolicyCommand {
    /// Grant a TSIG key nsupdate rights in a zone
    Add {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Name of an existing non-global TSIG key (global keys already cover
        /// every zone)
        #[arg(long, value_name = "KEY_NAME")]
        key: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact
        /// relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT'
        /// (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List a zone's TSIG policies
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Remove a TSIG policy from a zone by policy ID
    #[command(alias = "rm")]
    Remove {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// ID of the policy to remove (see `tsig-policy list`)
        #[arg(value_name = "POLICY_ID")]
        id: i32,
    },
}

pub(crate) async fn handle_command(subcommand: TsigPolicyCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    match subcommand {
        TsigPolicyCommand::Add {
            name,
            key,
            pattern,
            types,
            output,
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
            print_response(
                &response.data,
                output,
                |policy: &GetZoneTsigPolicyResponse| vec![ZoneTsigPolicyRow::from(policy)],
            )?;
        }
        TsigPolicyCommand::List { name, output } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneTsigPolicyList,
                    ZonePolicyListParams { zone_name: name },
                )
                .await?;
            print_response(
                &response.data,
                output,
                |policies: &Vec<GetZoneTsigPolicyResponse>| {
                    policies.iter().map(ZoneTsigPolicyRow::from).collect()
                },
            )?;
        }
        TsigPolicyCommand::Remove { name, id } => {
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
