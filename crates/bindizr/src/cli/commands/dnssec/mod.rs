//! The `dnssec` subcommands.

mod keys;

use bindizr_core::outln;
use bindizr_service::types::{
    DnssecStatusResponse, EnableDnssecRequest, RolloverDnssecRequest, UpdateDnssecSettingsRequest,
};
use clap::Subcommand;
pub(crate) use keys::DnssecKeysCommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            DnssecKeyRow, DnssecPolicyRow, OutputFormat, parse_response, print_payload, print_table,
        },
    },
    socket::{
        client,
        types::{
            DaemonCommandKind, DisableZoneDnssecParams, DsSeenZoneDnssecParams,
            EnableZoneDnssecParams, RolloverZoneDnssecParams, UpdateZoneDnssecSettingsParams,
            ZoneNameParams,
        },
    },
};

/// Subcommands for managing a zone's DNSSEC signing.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecCommand {
    /// Enable DNSSEC: generate the signing key(s) a policy prescribes and
    /// sign the zone
    Enable {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// DNSSEC policy to sign under (default: the built-in "default"
        /// policy; see `bindizr dnssec-policy list`)
        #[arg(long, value_name = "POLICY_NAME")]
        policy: Option<String>,
        /// The parent zone's nameservers (comma-separated host[:port]),
        /// asked for this zone's DS by `check-ds`, `rollover ds-seen`, and
        /// `disable`
        #[arg(long, value_name = "ADDRS")]
        parent_ns_addrs: String,
    },
    /// Change a zone's signing settings: the policy it signs under and/or
    /// the parent nameservers asked for its DS record
    #[command(group = clap::ArgGroup::new("setting").required(true).multiple(true))]
    Set {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Move to a policy with the same key layout; a new denial mode
        /// replaces the chain, and a new algorithm starts a rollover
        #[arg(long, value_name = "POLICY_NAME", group = "setting")]
        policy: Option<String>,
        /// Comma-separated host[:port] entries of the parent's nameservers;
        /// must name at least one server
        #[arg(long, value_name = "ADDRS", group = "setting")]
        parent_ns_addrs: Option<String>,
    },
    /// Publish or cancel the RFC 8078 delete CDS/CDNSKEY pair that asks a
    /// CDS-consuming parent to drop the zone's DS: the first step of going
    /// insecure
    Withdraw {
        #[command(subcommand)]
        subcommand: DnssecWithdrawCommand,
    },
    /// Disable DNSSEC: delete the zone's keys and signatures. Refused while
    /// the parent zone still serves this zone's DS record or cannot be asked;
    /// remove the DS and wait out its TTL first
    Disable {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Skip the parent DS check
        #[arg(long)]
        skip_ds_check: bool,
    },
    /// Ask the parent zone whether it serves this zone's DS record: the
    /// check that gates `disable`
    CheckDs {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show a zone's DNSSEC status (policy, keys, DS records, signature expiry)
    Status {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Re-sign a zone from scratch, discarding stored signatures
    Sign {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
    },
    /// Roll a zone's signing key: pre-publish a replacement, then promote it
    Rollover {
        #[command(subcommand)]
        subcommand: DnssecRolloverCommand,
    },
    /// Import or export the zone's raw keys (BIND `K*.key`/`K*.private` form)
    Keys {
        #[command(subcommand)]
        subcommand: DnssecKeysCommand,
    },
}

/// Subcommands for rolling a zone's signing keys.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecRolloverCommand {
    /// Publish a replacement key with the same algorithm. After the publish
    /// wait, maintenance promotes ZSKs automatically and CSK/KSKs once the
    /// parent serves their DS; `ds-seen` requests that confirmation manually
    Start {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Which key to roll: required for split-key zones (ksk or zsk),
        /// omitted for CSK zones
        #[arg(long, value_name = "ksk|zsk")]
        role: Option<String>,
    },
    /// Confirm the new DS is at the parent: once its nameservers serve the
    /// DS, promotes the pre-published key and retires the one it replaces.
    /// ZSK rollovers involve no DS and promote automatically
    DsSeen {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Take the DS on your word instead of asking the parent
        #[arg(long)]
        skip_ds_check: bool,
        /// Promote before the hold-down ends; resolvers still caching the
        /// previous keys fail until it expires (compromised key only)
        #[arg(long)]
        skip_holddown: bool,
    },
}

/// Subcommands for a zone's DS withdrawal.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecWithdrawCommand {
    /// Publish the delete pair (`CDS 0 0 0 00`) to request DS removal
    /// from a parent that processes CDS records
    Start {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
    },
    /// Take a published withdrawal back
    Cancel {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
    },
}

/// Run the requested DNSSEC lifecycle command.
pub(crate) async fn handle_command(subcommand: DnssecCommand) -> Result<(), CliError> {
    match subcommand {
        DnssecCommand::Enable {
            name,
            policy,
            parent_ns_addrs,
        } => {
            let response = client::send_command(
                DaemonCommandKind::EnableDnssec,
                EnableZoneDnssecParams {
                    zone_name: name,
                    request: EnableDnssecRequest {
                        policy,
                        parent_ns_addrs,
                    },
                },
            )
            .await?;
            print_status(&response.data)?;
        }
        DnssecCommand::CheckDs { name, output } => {
            let response =
                client::send_command(DaemonCommandKind::CheckDnssecDs, ZoneNameParams { name })
                    .await?;
            match output {
                OutputFormat::Table => print_status(&response.data)?,
                _ => print_payload(&response.data, output)?,
            }
        }
        DnssecCommand::Set {
            name,
            policy,
            parent_ns_addrs,
        } => {
            let response = client::send_command(
                DaemonCommandKind::UpdateDnssecSettings,
                UpdateZoneDnssecSettingsParams {
                    zone_name: name,
                    request: UpdateDnssecSettingsRequest {
                        policy,
                        parent_ns_addrs,
                    },
                },
            )
            .await?;
            print_status(&response.data)?;
        }
        DnssecCommand::Withdraw { subcommand } => {
            let (kind, name) = match subcommand {
                DnssecWithdrawCommand::Start { name } => (DaemonCommandKind::WithdrawDnssec, name),
                DnssecWithdrawCommand::Cancel { name } => {
                    (DaemonCommandKind::CancelDnssecWithdrawal, name)
                }
            };
            let response = client::send_command(kind, ZoneNameParams { name }).await?;
            print_status(&response.data)?;
        }
        DnssecCommand::Keys { subcommand } => keys::handle_command(subcommand).await?,
        DnssecCommand::Disable {
            name,
            skip_ds_check,
        } => {
            let response = client::send_command(
                DaemonCommandKind::DisableDnssec,
                DisableZoneDnssecParams {
                    zone_name: name,
                    skip_ds_check,
                },
            )
            .await?;
            outln!("{}", response.message);
        }
        DnssecCommand::Status { name, output } => {
            let response =
                client::send_command(DaemonCommandKind::GetDnssecStatus, ZoneNameParams { name })
                    .await?;
            match output {
                OutputFormat::Table => print_status(&response.data)?,
                _ => print_payload(&response.data, output)?,
            }
        }
        DnssecCommand::Sign { name } => {
            let response =
                client::send_command(DaemonCommandKind::SignZone, ZoneNameParams { name }).await?;
            outln!("{}", response.message);
        }
        DnssecCommand::Rollover { subcommand } => match subcommand {
            DnssecRolloverCommand::Start { name, role } => {
                let response = client::send_command(
                    DaemonCommandKind::StartDnssecRollover,
                    RolloverZoneDnssecParams {
                        zone_name: name,
                        request: RolloverDnssecRequest { role },
                    },
                )
                .await?;
                print_status(&response.data)?;
            }
            DnssecRolloverCommand::DsSeen {
                name,
                skip_ds_check,
                skip_holddown,
            } => {
                let response = client::send_command(
                    DaemonCommandKind::DsSeenDnssecRollover,
                    DsSeenZoneDnssecParams {
                        zone_name: name,
                        skip_ds_check,
                        skip_holddown,
                    },
                )
                .await?;
                print_status(&response.data)?;
            }
        },
    }

    Ok(())
}

/// Print the zone's DNSSEC status and key information.
fn print_status(data: &serde_json::Value) -> Result<(), String> {
    let status = parse_response::<DnssecStatusResponse>(data)?.dnssec;
    let Some(policy) = status.policy.as_ref().filter(|_| status.enabled) else {
        outln!(
            "Zone {} (serial {}): DNSSEC disabled",
            status.zone_name,
            status.serial
        );
        return Ok(());
    };

    outln!(
        "Zone {} (serial {}): DNSSEC enabled, {} denial",
        status.zone_name,
        status.serial,
        policy.denial.to_uppercase()
    );
    if status.withdrawing {
        outln!(
            "DS withdrawal published (RFC 8078): the parent should drop this zone's DS records."
        );
    }
    if let Some(addrs) = status.parent_ns_addrs.as_deref() {
        outln!("Parent nameservers: {}", addrs);
    }
    if let Some(delegation) = &status.delegation {
        let servers = delegation.parent_ns_addrs.join(", ");
        if delegation.ds_key_tags.is_empty() {
            outln!("Parent DS: none served by {}", servers);
        } else {
            outln!(
                "Parent DS: key tag{} {} served by {} (TTL {}s)",
                if delegation.ds_key_tags.len() == 1 {
                    ""
                } else {
                    "s"
                },
                delegation
                    .ds_key_tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                servers,
                delegation.ds_ttl.unwrap_or(0)
            );
        }
        for key in &delegation.keys {
            let mut line = format!(
                "  {} ({}, {}): {}",
                key.key_tag,
                key.role,
                key.state,
                match (key.ds_published, key.ds_digest_unsupported) {
                    (true, _) => "at parent",
                    (false, true) => "at parent in a digest type bindizr cannot check",
                    (false, false) => "not at parent",
                }
            );
            if let Some(eligible_at) = key.eligible_at {
                line.push_str(&format!(
                    ", promotable from {}",
                    eligible_at.format("%Y-%m-%d %H:%M:%S")
                ));
            }
            outln!("{}", line);
        }
    }
    if let Some(expires_at) = status.earliest_signature_expires_at {
        outln!(
            "Earliest signature expiry: {}",
            expires_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
    if let Some(resign_at) = status.next_resign_at {
        outln!("Next re-signing: {}", resign_at.format("%Y-%m-%d %H:%M:%S"));
    }
    if status.expired_signatures == 0 {
        outln!("Signatures: {}", status.signatures);
    } else {
        // Resolvers are already failing this much of the zone.
        outln!(
            "Signatures: {} ({} EXPIRED)",
            status.signatures,
            status.expired_signatures
        );
    }
    outln!("Policy:");
    print_table(vec![DnssecPolicyRow::from(policy)]);
    outln!("Keys:");
    print_table(status.keys.iter().map(DnssecKeyRow::from).collect());
    if !status.ds_records.is_empty() {
        outln!("DS records (register in the parent zone):");
        for ds in &status.ds_records {
            outln!("  {}", ds.presentation);
        }
    }

    Ok(())
}
