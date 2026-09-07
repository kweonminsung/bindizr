//! The `dnssec` subcommands.

mod keys;

use bindizr_service::types::{
    EnableDnssecRequest, GetDnssecStatusResponse, RolloverDnssecRequest,
    SetDnssecParentNsAddrsRequest, SetZoneDnssecPolicyRequest,
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
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, DisableZoneDnssecParams, DsSeenZoneDnssecParams,
            EnableZoneDnssecParams, RolloverZoneDnssecParams, SetZoneDnssecParentNsAddrsParams,
            SetZoneDnssecPolicyParams, ZoneNameParams,
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
        /// The parent zone's nameservers (comma-separated host[:port]) asked
        /// for this zone's DS before DNSSEC is disabled (default: discovered)
        #[arg(long, value_name = "ADDRS")]
        parent_ns_addrs: Option<String>,
    },
    /// Set a signed zone's policy or its parent's nameservers
    Set {
        #[command(subcommand)]
        subcommand: DnssecSetCommand,
    },
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure
    Withdraw {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Cancel a published withdrawal instead
        #[arg(long)]
        cancel: bool,
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
    /// Print a zone's DS records for pasting into the parent zone
    Ds {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
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

/// Subcommands setting one attribute of a zone's signing.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecSetCommand {
    /// Move a signed zone to another DNSSEC policy. The denial mode and key
    /// layout must match; a different algorithm starts an algorithm rollover
    Policy {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Name of the target policy
        #[arg(value_name = "POLICY_NAME")]
        policy: String,
    },
    /// Set the parent zone's nameservers asked for this zone's DS record,
    /// or clear them so the parent is discovered again
    ParentNsAddrs {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Comma-separated host[:port] entries of the parent's nameservers
        #[arg(
            value_name = "ADDRS",
            required_unless_present = "clear",
            conflicts_with = "clear"
        )]
        addrs: Option<String>,
        /// Return the zone to parent discovery
        #[arg(long)]
        clear: bool,
    },
}

/// Subcommands for rolling a zone's signing keys.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecRolloverCommand {
    /// Pre-publish a same-algorithm replacement key: it joins the DNSKEY
    /// and CDS/CDNSKEY records but signs no zone data until `ds-seen`
    /// promotes it. To change the algorithm, use `dnssec set policy`
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

pub(crate) async fn handle_command(subcommand: DnssecCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    match subcommand {
        DnssecCommand::Enable {
            name,
            policy,
            parent_ns_addrs,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecEnable,
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
        DnssecCommand::CheckDs { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecCheckDs,
                    ZoneNameParams { name },
                )
                .await?;
            print_status(&response.data)?;
        }
        DnssecCommand::Set { subcommand } => match subcommand {
            DnssecSetCommand::Policy { name, policy } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecSetPolicy,
                        SetZoneDnssecPolicyParams {
                            zone_name: name,
                            request: SetZoneDnssecPolicyRequest { policy },
                        },
                    )
                    .await?;
                print_status(&response.data)?;
            }
            DnssecSetCommand::ParentNsAddrs { name, addrs, clear } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecSetParentNsAddrs,
                        SetZoneDnssecParentNsAddrsParams {
                            zone_name: name,
                            request: SetDnssecParentNsAddrsRequest {
                                parent_ns_addrs: if clear { None } else { addrs },
                            },
                        },
                    )
                    .await?;
                print_status(&response.data)?;
            }
        },
        DnssecCommand::Withdraw { name, cancel } => {
            let kind = if cancel {
                DaemonCommandKind::ZoneDnssecWithdrawCancel
            } else {
                DaemonCommandKind::ZoneDnssecWithdraw
            };
            let response = client.send_command(kind, ZoneNameParams { name }).await?;
            print_status(&response.data)?;
        }
        DnssecCommand::Keys { subcommand } => keys::handle_command(&client, subcommand).await?,
        DnssecCommand::Disable {
            name,
            skip_ds_check,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecDisable,
                    DisableZoneDnssecParams {
                        zone_name: name,
                        skip_ds_check,
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        DnssecCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            match output {
                OutputFormat::Table => print_status(&response.data)?,
                _ => print_payload(&response.data, output)?,
            }
        }
        DnssecCommand::Ds { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_ds_records(&response.data)?;
        }
        DnssecCommand::Sign { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecSign, ZoneNameParams { name })
                .await?;
            println!("{}", response.message);
        }
        DnssecCommand::Rollover { subcommand } => match subcommand {
            DnssecRolloverCommand::Start { name, role } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverStart,
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
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverDsSeen,
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

pub(crate) fn print_status(data: &serde_json::Value) -> Result<(), String> {
    let status: GetDnssecStatusResponse = parse_response(data)?;
    let Some(policy) = status.policy.as_ref().filter(|_| status.enabled) else {
        println!(
            "Zone {} (serial {}): DNSSEC disabled",
            status.zone_name, status.serial
        );
        return Ok(());
    };

    println!(
        "Zone {} (serial {}): DNSSEC enabled, {} denial",
        status.zone_name,
        status.serial,
        policy.denial.to_uppercase()
    );
    if status.withdrawing {
        println!(
            "DS withdrawal published (RFC 8078): the parent should drop this zone's DS records."
        );
    }
    match status.parent_ns_addrs.as_deref() {
        Some(addrs) => println!("Parent nameservers: {}", addrs),
        None => println!("Parent nameservers: discovered through the system resolver"),
    }
    if let Some(delegation) = &status.delegation {
        let servers = delegation.parent_servers.join(", ");
        if delegation.ds_key_tags.is_empty() {
            println!("Parent DS: none served by {}", servers);
        } else {
            println!(
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
                if key.ds_published {
                    "at parent"
                } else {
                    "not at parent"
                }
            );
            if let Some(eligible_at) = key.eligible_at {
                line.push_str(&format!(
                    ", promotable from {}",
                    eligible_at.format("%Y-%m-%d %H:%M:%S")
                ));
            }
            println!("{}", line);
        }
    }
    if let Some(expires_at) = status.earliest_signature_expires_at {
        println!(
            "Earliest signature expiry: {}",
            expires_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
    println!("Policy:");
    print_table(vec![DnssecPolicyRow::from(policy)]);
    println!("Keys:");
    print_table(status.keys.iter().map(DnssecKeyRow::from).collect());
    if !status.ds_records.is_empty() {
        println!("DS records (register in the parent zone):");
        for ds in &status.ds_records {
            println!("  {}", ds.presentation);
        }
    }

    Ok(())
}

fn print_ds_records(data: &serde_json::Value) -> Result<(), String> {
    let status: GetDnssecStatusResponse = parse_response(data)?;

    if status.ds_records.is_empty() {
        println!("No DS records found");
        return Ok(());
    }

    if status.withdrawing {
        println!("# DS withdrawal published: do not register these at the parent.");
    }
    // Plain presentation lines only, so the output pastes into a parent zone.
    for ds in &status.ds_records {
        println!("{}", ds.presentation);
    }

    Ok(())
}
