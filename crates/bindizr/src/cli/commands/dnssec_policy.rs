use bindizr_core::log_debug;
use bindizr_service::types::{
    CreateDnssecPolicyRequest, GetDnssecPolicyResponse, UpdateDnssecPolicyRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{DnssecPolicyRow, OutputFormat, print_response},
    },
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, DnssecPolicyNameParams, UpdateDnssecPolicyParams},
    },
};

/// Subcommands for managing DNSSEC policies, the named signing-parameter
/// bundles zones sign under.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecPolicyCommand {
    /// Create a DNSSEC policy (omitted options take the built-in defaults)
    Create {
        /// Policy name (letters, digits, '-', '_', '.')
        #[arg(long, value_name = "POLICY_NAME")]
        name: String,
        /// Signing algorithm: ecdsap256sha256 (default), ecdsap384sha384, ed25519, ed448, rsasha256, or rsasha512. Fixed at creation
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Denial-of-existence mode: nsec (default) or nsec3. Fixed at creation
        #[arg(long, value_name = "nsec|nsec3")]
        denial: Option<String>,
        /// Generate split KSK/ZSK keys instead of one CSK, so the ZSK rolls
        /// without touching the parent zone's DS. Fixed at creation
        #[arg(long)]
        split_keys: bool,
        /// Days a new signature stays valid (default 14)
        #[arg(long, value_name = "DAYS")]
        signature_validity_days: Option<u32>,
        /// Re-sign when a signature has fewer than this many days left (default 5)
        #[arg(long, value_name = "DAYS")]
        signature_refresh_days: Option<u32>,
        /// Days an active ZSK may sign before the scheduler rolls it (0, the
        /// default, disables scheduled rolls)
        #[arg(long, value_name = "DAYS")]
        zsk_lifetime_days: Option<u32>,
        /// Wait before a pre-published key may start signing (default 86400)
        #[arg(long, value_name = "SECS")]
        rollover_publish_holddown_secs: Option<u32>,
        /// Wait before a retired key is removed from the zone (default 172800)
        #[arg(long, value_name = "SECS")]
        rollover_retire_holddown_secs: Option<u32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List all DNSSEC policies
    #[command(alias = "ls")]
    List {
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show one DNSSEC policy
    Get {
        /// Name of the policy
        #[arg(value_name = "POLICY_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Edit a policy's timing; an omitted option keeps its value. The
    /// algorithm, denial mode, and key layout cannot change
    Update {
        /// Name of the policy
        #[arg(value_name = "POLICY_NAME")]
        name: String,
        /// Days a new signature stays valid
        #[arg(long, value_name = "DAYS")]
        signature_validity_days: Option<u32>,
        /// Re-sign when a signature has fewer than this many days left
        #[arg(long, value_name = "DAYS")]
        signature_refresh_days: Option<u32>,
        /// Days an active ZSK may sign before the scheduler rolls it (0
        /// disables scheduled rolls)
        #[arg(long, value_name = "DAYS")]
        zsk_lifetime_days: Option<u32>,
        /// Wait before a pre-published key may start signing
        #[arg(long, value_name = "SECS")]
        rollover_publish_holddown_secs: Option<u32>,
        /// Wait before a retired key is removed from the zone
        #[arg(long, value_name = "SECS")]
        rollover_retire_holddown_secs: Option<u32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Delete a DNSSEC policy (refused for the built-in "default" and while
    /// any zone signs under it)
    #[command(alias = "rm")]
    Delete {
        /// Name of the policy
        #[arg(value_name = "POLICY_NAME")]
        name: String,
    },
}

/// Handle the `dnssec-policy` subcommand by dispatching to the daemon over
/// the socket.
pub(crate) async fn handle_command(subcommand: DnssecPolicyCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        DnssecPolicyCommand::Create {
            name,
            algorithm,
            denial,
            split_keys,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            rollover_publish_holddown_secs,
            rollover_retire_holddown_secs,
            output,
        } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyCreate,
                    CreateDnssecPolicyRequest {
                        name,
                        algorithm,
                        denial,
                        split_keys,
                        signature_validity_days,
                        signature_refresh_days,
                        zsk_lifetime_days,
                        rollover_publish_holddown_secs,
                        rollover_retire_holddown_secs,
                    },
                )
                .await?;

            log_debug!("DNSSEC policy creation result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::List { output } => {
            let res = client
                .send_command(DaemonCommandKind::DnssecPolicyList, ())
                .await?;

            log_debug!("DNSSEC policy list result: {:?}", res);

            print_response(
                &res.data,
                output,
                |policies: &Vec<GetDnssecPolicyResponse>| {
                    policies.iter().map(DnssecPolicyRow::from).collect()
                },
            )?;
        }
        DnssecPolicyCommand::Get { name, output } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyGet,
                    DnssecPolicyNameParams { name },
                )
                .await?;

            log_debug!("DNSSEC policy get result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::Update {
            name,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            rollover_publish_holddown_secs,
            rollover_retire_holddown_secs,
            output,
        } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyUpdate,
                    UpdateDnssecPolicyParams {
                        name,
                        request: UpdateDnssecPolicyRequest {
                            signature_validity_days,
                            signature_refresh_days,
                            zsk_lifetime_days,
                            rollover_publish_holddown_secs,
                            rollover_retire_holddown_secs,
                        },
                    },
                )
                .await?;

            log_debug!("DNSSEC policy update result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::Delete { name } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyDelete,
                    DnssecPolicyNameParams { name },
                )
                .await?;

            log_debug!("DNSSEC policy deletion result: {:?}", res);

            println!("{}", res.message);
        }
    }

    Ok(())
}

fn print_policy(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |policy: &GetDnssecPolicyResponse| {
        vec![DnssecPolicyRow::from(policy)]
    })
}
