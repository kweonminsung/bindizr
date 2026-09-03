//! The `zone dnssec` subcommands.

use bindizr_service::types::{
    EnableDnssecRequest, ExportDnssecKeysResponse, GetDnssecStatusResponse, ImportDnssecKeyPair,
    ImportDnssecKeyRequest, RolloverDnssecRequest, SetZoneDnssecPolicyRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{DnssecKeyRow, OutputFormat, parse_response, print_response, print_table},
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, EnableZoneDnssecParams, ImportZoneDnssecKeyParams,
            RolloverZoneDnssecParams, SetZoneDnssecPolicyParams, ZoneNameParams,
        },
    },
};

/// Subcommands for managing a zone's DNSSEC signing.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecCommand {
    /// Enable DNSSEC: generate the signing key(s) a policy prescribes and
    /// sign the zone
    Enable {
        /// The name of the zone
        name: String,
        /// DNSSEC policy to sign under (default: the built-in "default"
        /// policy; see `bindizr dnssec-policy list`)
        #[arg(long, value_name = "NAME")]
        policy: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Move a signed zone to another DNSSEC policy. The denial mode and key
    /// layout must match; a different algorithm starts an algorithm rollover
    SetPolicy {
        /// The name of the zone
        name: String,
        /// Name of the target policy
        policy: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure
    Withdraw {
        /// The name of the zone
        name: String,
        /// Cancel a published withdrawal instead
        #[arg(long)]
        cancel: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Disable DNSSEC: delete the zone's keys and signatures. Remove the DS
    /// record from the parent zone and wait out its TTL first, or validating
    /// resolvers will treat the zone as bogus
    Disable {
        /// The name of the zone
        name: String,
    },
    /// Show a zone's DNSSEC status (policy, keys, DS records, signature expiry)
    Status {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Print a zone's DS records for pasting into the parent zone
    Ds {
        /// The name of the zone
        name: String,
    },
    /// Re-sign a zone from scratch, discarding stored signatures
    Sign {
        /// The name of the zone
        name: String,
    },
    /// Roll a zone's signing key: pre-publish a replacement, then promote it
    Rollover {
        #[command(subcommand)]
        subcommand: ZoneDnssecRolloverCommand,
    },
    /// Import or export the zone's raw keys (BIND `K*.key`/`K*.private` form)
    Keys {
        #[command(subcommand)]
        subcommand: ZoneDnssecKeysCommand,
    },
}

/// Subcommands for rolling a zone's signing keys.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecRolloverCommand {
    /// Pre-publish a same-algorithm replacement key: it joins the DNSKEY
    /// RRset and CDS/CDNSKEY set but signs no zone data until `ds-seen`
    /// promotes it. To change the algorithm, use `zone dnssec set-policy`
    Start {
        /// The name of the zone
        name: String,
        /// Which key to roll: required for split-key zones (ksk or zsk),
        /// omitted for CSK zones
        #[arg(long, value_name = "ksk|zsk")]
        role: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Confirm the new DS has been seen at the parent (and its TTL has
    /// passed): promotes the pre-published key and retires the one it
    /// replaces. ZSK rollovers involve no DS and promote automatically
    DsSeen {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

/// Subcommands for moving raw key material in and out of bindizr.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecKeysCommand {
    /// Print the zone's keys in BIND key-file form, private halves
    /// included — redirect somewhere with tight permissions
    Export {
        /// The name of the zone
        name: String,
    },
    /// Import the zone's key set as BIND key pairs and sign it: one CSK
    /// pair, or a KSK pair and a ZSK pair for a split-key policy. The
    /// migration path for a zone signed elsewhere; the zone must be unsigned
    Import {
        /// The name of the zone
        name: String,
        /// Path to a K*.key file (the DNSKEY record); repeat with --private
        /// for each pair
        #[arg(long, value_name = "FILE", required = true)]
        key: Vec<String>,
        /// Path to the matching K*.private file, in the same order as --key
        #[arg(long, value_name = "FILE", required = true)]
        private: Vec<String>,
        /// Policy the zone signs under (default: "default"); its algorithm
        /// and key layout decide what the keys must be
        #[arg(long, value_name = "NAME")]
        policy: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub(crate) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneDnssecCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneDnssecCommand::Enable {
            name,
            policy,
            output,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecEnable,
                    EnableZoneDnssecParams {
                        zone_name: name,
                        request: EnableDnssecRequest { policy },
                    },
                )
                .await?;
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::SetPolicy {
            name,
            policy,
            output,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecSetPolicy,
                    SetZoneDnssecPolicyParams {
                        zone_name: name,
                        request: SetZoneDnssecPolicyRequest { policy },
                    },
                )
                .await?;
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Withdraw {
            name,
            cancel,
            output,
        } => {
            let kind = if cancel {
                DaemonCommandKind::ZoneDnssecWithdrawCancel
            } else {
                DaemonCommandKind::ZoneDnssecWithdraw
            };
            let response = client.send_command(kind, ZoneNameParams { name }).await?;
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Keys { subcommand } => match subcommand {
            ZoneDnssecKeysCommand::Export { name } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecKeysExport,
                        ZoneNameParams { name },
                    )
                    .await?;
                let exported: ExportDnssecKeysResponse =
                    parse_response(&response.data).map_err(CliError::from)?;
                print_key_material(&exported);
            }
            ZoneDnssecKeysCommand::Import {
                name,
                key,
                private,
                policy,
                output,
            } => {
                if key.len() != private.len() {
                    return Err(CliError::from(format!(
                        "--key and --private must be given in pairs ({} and {})",
                        key.len(),
                        private.len()
                    )));
                }
                let mut keys = Vec::with_capacity(key.len());
                for (key, private) in key.iter().zip(&private) {
                    let dnskey = std::fs::read_to_string(key)
                        .map_err(|e| CliError::from(format!("Failed to read '{}': {}", key, e)))?;
                    let private_key = std::fs::read_to_string(private).map_err(|e| {
                        CliError::from(format!("Failed to read '{}': {}", private, e))
                    })?;
                    keys.push(ImportDnssecKeyPair {
                        dnskey,
                        private_key,
                    });
                }
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecKeysImport,
                        ImportZoneDnssecKeyParams {
                            zone_name: name,
                            request: ImportDnssecKeyRequest { keys, policy },
                        },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
        },
        ZoneDnssecCommand::Disable { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecDisable,
                    ZoneNameParams { name },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Ds { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_ds_records(&response.data)?;
        }
        ZoneDnssecCommand::Sign { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecSign, ZoneNameParams { name })
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Rollover { subcommand } => match subcommand {
            ZoneDnssecRolloverCommand::Start { name, role, output } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverStart,
                        RolloverZoneDnssecParams {
                            zone_name: name,
                            request: RolloverDnssecRequest { role },
                        },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
            ZoneDnssecRolloverCommand::DsSeen { name, output } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverDsSeen,
                        ZoneNameParams { name },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
        },
    }

    Ok(())
}

fn print_status(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    if output != OutputFormat::Table {
        return print_response(data, output, |status: &GetDnssecStatusResponse| {
            status.keys.iter().map(DnssecKeyRow::from).collect()
        });
    }

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
    println!(
        "Policy: {} ({}, {}; validity {}d, refresh {}d, zsk-lifetime {}d)",
        policy.name,
        policy.algorithm,
        if policy.split_keys { "KSK/ZSK" } else { "CSK" },
        policy.signature_validity_days,
        policy.signature_refresh_days,
        policy.zsk_lifetime_days
    );
    if status.withdrawing {
        println!(
            "DS withdrawal published (RFC 8078): the parent should drop this zone's DS records."
        );
    }
    if let Some(expires_at) = status.earliest_signature_expires_at {
        println!(
            "Earliest signature expiry: {}",
            expires_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
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

/// Print each key as its BIND file pair, headed by the file name BIND
/// tooling expects, so the stream splits cleanly into `K*.key`/`K*.private`.
fn print_key_material(exported: &ExportDnssecKeysResponse) {
    for (i, key) in exported.keys.iter().enumerate() {
        let mut base = format!(
            "K{}.+{:03}+{:05}",
            exported.zone_name, key.algorithm, key.key_tag
        );
        // Distinct keys may share (algorithm, tag); the suffix keeps names unique.
        let dup = exported.keys[..i]
            .iter()
            .filter(|k| k.algorithm == key.algorithm && k.key_tag == key.key_tag)
            .count();
        if dup > 0 {
            base.push_str(&format!(".{}", dup + 1));
        }
        println!("; {}.key ({}, tag {})", base, key.role, key.key_tag);
        println!("{}", key.dnskey_record);
        println!("; {}.private", base);
        println!("{}", key.private_key.trim_end());
    }
}
