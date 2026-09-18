use bindizr_core::outln;
use bindizr_service::types::{
    CreateDnssecPolicyRequest, DnssecPolicyResponse, GetDnssecPolicyResponse, PageFilter,
    PaginatedResponse, UpdateDnssecPolicyRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{DnssecPolicyRow, OutputFormat, print_response},
    },
    socket::{
        client,
        types::{DaemonCommandKind, DnssecPolicyNameParams, UpdateDnssecPolicyParams},
    },
};

/// Subcommands for managing DNSSEC policies, the named signing-parameter
/// bundles zones sign under.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecPolicyCommand {
    /// Create a DNSSEC policy (omitted options take the built-in defaults)
    #[command(after_help = "\
Examples:
  bindizr dnssec-policy create strict --algorithm ed25519
  bindizr dnssec-policy create split --split-keys --zsk-lifetime-days 90

--algorithm, --denial and --split-keys are fixed at creation, because changing
them rebuilds the zone's key set; the day counts stay editable with
`dnssec-policy update`.")]
    Create {
        /// Policy name (letters, digits, '-', '_', '.')
        #[arg(value_name = "POLICY_NAME")]
        name: String,
        /// Signing algorithm: ecdsap256sha256 (default), ecdsap384sha384, ed25519, ed448, rsasha256, or rsasha512. Fixed at creation
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Denial-of-existence mode: nsec3 (default) or nsec. Fixed at creation
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
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List all DNSSEC policies
    #[command(alias = "ls")]
    List {
        /// Maximum number of policies to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of policies to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show one DNSSEC policy
    Get {
        /// Name of the policy
        #[arg(value_name = "POLICY_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
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
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
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
    match subcommand {
        DnssecPolicyCommand::Create {
            name,
            algorithm,
            denial,
            split_keys,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateDnssecPolicy,
                CreateDnssecPolicyRequest {
                    name,
                    algorithm,
                    denial,
                    split_keys,
                    signature_validity_days,
                    signature_refresh_days,
                    zsk_lifetime_days,
                },
            )
            .await?;

            log::debug!("DNSSEC policy creation result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::List {
            limit,
            offset,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::ListDnssecPolicies,
                PageFilter { limit, offset },
            )
            .await?;

            log::debug!("DNSSEC policy list result: {:?}", res);

            print_response(
                &res.data,
                output,
                |policies: &PaginatedResponse<GetDnssecPolicyResponse>| {
                    policies.items.iter().map(DnssecPolicyRow::from).collect()
                },
            )?;
        }
        DnssecPolicyCommand::Get { name, output } => {
            let res = client::send_command(
                DaemonCommandKind::GetDnssecPolicy,
                DnssecPolicyNameParams { name },
            )
            .await?;

            log::debug!("DNSSEC policy get result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::Update {
            name,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::UpdateDnssecPolicy,
                UpdateDnssecPolicyParams {
                    name,
                    request: UpdateDnssecPolicyRequest {
                        signature_validity_days,
                        signature_refresh_days,
                        zsk_lifetime_days,
                    },
                },
            )
            .await?;

            log::debug!("DNSSEC policy update result: {:?}", res);

            print_policy(&res.data, output)?;
        }
        DnssecPolicyCommand::Delete { name } => {
            let res = client::send_command(
                DaemonCommandKind::DeleteDnssecPolicy,
                DnssecPolicyNameParams { name },
            )
            .await?;

            log::debug!("DNSSEC policy deletion result: {:?}", res);

            outln!("{}", res.message);
        }
    }

    Ok(())
}

/// Print a DNSSEC policy in the selected output format.
fn print_policy(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |response: &DnssecPolicyResponse| {
        vec![DnssecPolicyRow::from(&response.dnssec_policy)]
    })
}
