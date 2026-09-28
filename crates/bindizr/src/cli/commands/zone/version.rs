//! The `zone version` subcommands: list, show, diff, and rollback.

use bindizr_core::{model::zone_version::VersionScope, out, outln};
use bindizr_service::types::{
    PaginatedResponse, RollbackZoneResponse, Run, VersionDetailResponse, VersionDiffResponse,
    ZoneVersionResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            OutputFormat, RollbackSummaryRow, VersionRecordRow, VersionRow, print_page,
            print_payload, print_table, render_version_diff,
        },
    },
    socket::{client, types::DaemonCommand},
};

/// Subcommands for inspecting a zone's versions.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneVersionCommand {
    /// List a zone's versions (serial history)
    #[command(
        alias = "ls",
        after_help = "\
Examples:
  bindizr zone version list example.com
  bindizr zone version list example.com --include-signer-serials

By default only serials a user change produced are listed; re-signs and
rollovers move the serial too, and --include-signer-serials shows those."
    )]
    List {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Maximum number of versions to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of versions to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Include signer-only serials (DNSSEC re-signs and rollovers)
        #[arg(long)]
        include_signer_serials: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show the zone state captured at one version serial
    #[command(after_help = "\
Examples:
  bindizr zone version get example.com 2026010101

`zone version list` prints the serials.")]
    Get {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Version serial to inspect
        serial: u32,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show the record differences between two serials
    #[command(after_help = "\
Examples:
  bindizr zone version diff example.com 2026010101 2026010105
  bindizr zone version diff example.com 2026010101

Omit the second serial to compare that version against the zone as it stands.")]
    Diff {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// The serial to diff from
        from_serial: u32,
        /// The serial to diff to (omit to compare against the current serial)
        to_serial: Option<u32>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Roll a zone back to the state captured at a version serial
    #[command(after_help = "\
Examples:
  bindizr zone version rollback example.com 2026010101 --dry-run
  bindizr zone version rollback example.com 2026010101

The zone serial still advances, so secondaries transfer the rollback as an
ordinary change rather than seeing the serial go backwards.")]
    Rollback {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Target version serial (the zone serial still advances)
        serial: u32,
        /// Compute and report the rollback without applying any change
        #[arg(long)]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Run the requested zone history or rollback command.
pub(crate) async fn handle_command(subcommand: ZoneVersionCommand) -> Result<(), CliError> {
    match subcommand {
        ZoneVersionCommand::List {
            name,
            limit,
            offset,
            include_signer_serials,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<ZoneVersionResponse>>(
                DaemonCommand::ListZoneVersions {
                    name,
                    limit,
                    offset,
                    scope: VersionScope::from_include_signer_serials(include_signer_serials),
                },
            )
            .await?;
            print_page(&response.data, output, |item| VersionRow::from(item))?;
        }
        ZoneVersionCommand::Get {
            name,
            serial,
            output,
        } => {
            let response =
                client::send_command::<VersionDetailResponse>(DaemonCommand::GetZoneVersion {
                    name,
                    serial,
                })
                .await?;
            let detail = &response.data;
            match output {
                OutputFormat::Table => {
                    print_table(vec![VersionRow::from(&detail.version)]);
                    print_table(detail.records.iter().map(VersionRecordRow::from).collect());
                }
                _ => print_payload(detail, output)?,
            }
        }
        ZoneVersionCommand::Diff {
            name,
            from_serial,
            to_serial,
            output,
        } => {
            let response =
                client::send_command::<VersionDiffResponse>(DaemonCommand::DiffZoneVersions {
                    name,
                    from_serial,
                    to_serial,
                })
                .await?;
            match output {
                OutputFormat::Table => out!("{}", render_version_diff(&response.data)),
                _ => print_payload(&response.data, output)?,
            }
        }
        ZoneVersionCommand::Rollback {
            name,
            serial,
            dry_run,
            output,
        } => {
            let response =
                client::send_command::<RollbackZoneResponse>(DaemonCommand::RollbackZone {
                    name,
                    serial,
                    run: Run::from_dry_run(dry_run),
                })
                .await?;
            match output {
                OutputFormat::Table => {
                    outln!("{}", response.message);
                    print_table(vec![RollbackSummaryRow::from(&response.data)]);
                }
                _ => print_payload(&response.data, output)?,
            }
        }
    }
    Ok(())
}
