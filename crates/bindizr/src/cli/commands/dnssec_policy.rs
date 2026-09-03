use bindizr_core::log_debug;
use bindizr_service::types::{
    CreateDnssecPolicyRequest, GetDnssecPolicyResponse, UpdateDnssecPolicyRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{DnssecPolicyRow, parse_response, print_table},
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
        #[arg(long)]
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
    },
    /// List all DNSSEC policies
    #[command(alias = "ls")]
    List,
    /// Show one DNSSEC policy
    Get {
        /// Name of the policy
        name: String,
    },
    /// Edit a policy's timing; an omitted option keeps its value. The
    /// algorithm, denial mode, and key layout cannot change
    Update {
        /// Name of the policy
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
    },
    /// Delete a DNSSEC policy (refused while any zone signs under it)
    #[command(alias = "rm")]
    Delete {
        /// Name of the policy
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

            let policy: GetDnssecPolicyResponse = parse_response(&res.data)?;
            println!("DNSSEC policy created successfully:");
            print_policy(&policy);
        }
        DnssecPolicyCommand::List => {
            let res = client
                .send_command(DaemonCommandKind::DnssecPolicyList, ())
                .await?;

            log_debug!("DNSSEC policy list result: {:?}", res);

            let policies: Vec<GetDnssecPolicyResponse> = parse_response(&res.data)?;
            print_table(policies.iter().map(DnssecPolicyRow::from).collect());
        }
        DnssecPolicyCommand::Get { name } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyGet,
                    DnssecPolicyNameParams { name },
                )
                .await?;

            log_debug!("DNSSEC policy get result: {:?}", res);

            let policy: GetDnssecPolicyResponse = parse_response(&res.data)?;
            print_policy(&policy);
        }
        DnssecPolicyCommand::Update {
            name,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            rollover_publish_holddown_secs,
            rollover_retire_holddown_secs,
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

            let policy: GetDnssecPolicyResponse = parse_response(&res.data)?;
            println!("DNSSEC policy updated successfully:");
            print_policy(&policy);
        }
        DnssecPolicyCommand::Delete { name } => {
            let res = client
                .send_command(
                    DaemonCommandKind::DnssecPolicyDelete,
                    DnssecPolicyNameParams { name },
                )
                .await?;

            log_debug!("DNSSEC policy deletion result: {:?}", res);

            println!("DNSSEC policy deleted successfully");
        }
    }

    Ok(())
}

fn print_policy(policy: &GetDnssecPolicyResponse) {
    println!("ID: {}", policy.id);
    println!("Name: {}", policy.name);
    println!("Algorithm: {}", policy.algorithm);
    println!("Denial: {}", policy.denial.to_uppercase());
    println!(
        "Keys: {}",
        if policy.split_keys { "KSK/ZSK" } else { "CSK" }
    );
    println!(
        "Signature validity: {}d (re-sign with {}d left)",
        policy.signature_validity_days, policy.signature_refresh_days
    );
    println!("ZSK lifetime: {}d", policy.zsk_lifetime_days);
    println!(
        "Rollover hold-downs: publish {}s, retire {}s",
        policy.rollover_publish_holddown_secs, policy.rollover_retire_holddown_secs
    );
    println!(
        "Created at: {}",
        policy.created_at.format("%Y-%m-%d %H:%M:%S")
    );
}
