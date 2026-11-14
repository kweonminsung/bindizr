use bindizr_service::types::{AuditLogFilter, AuditLogResponse, PaginatedResponse};
use chrono::{DateTime, Utc};
use clap::Subcommand;

use crate::cli::error::CliError;
use crate::cli::output::{AuditLogRow, OutputFormat};
use crate::cli::{output, time};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for reading the audit log.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditCommand {
    /// List the management changes, newest first: who changed what, and when
    #[command(
        alias = "ls",
        after_help = "\
Examples:
  bindizr audit list
  bindizr audit list --entity token --name external-dns
  bindizr audit list --since 7d -o json
  bindizr audit list --since 2026-10-01 --until 2026-11-01
  bindizr audit list --sort entity_name --order asc

A time is a span ago (7d, 12h, 30m), a date (2026-10-01, midnight UTC as the
AT column is), or an RFC 3339 timestamp.

A change to a token, role, grant, TSIG key, secondary or DNSSEC policy, and a
zone's deletion, is logged with the request path and the token that made it;
a socket command names no token. Changes to zone data are in the zone's
versions (`zone version list`) instead."
    )]
    List {
        /// Only changes to this kind of entity: token, role, role_grant,
        /// tsig_key, secondary, dnssec_policy, or zone
        #[arg(long, value_name = "ENTITY")]
        entity: Option<String>,
        /// Only changes to the entity of this name (a grant's is its role's)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Only changes at or after this time: a span ago (7d, 12h, 30m), a
        /// UTC date (2026-10-01), or RFC 3339
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only changes before this time, in the same forms
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        until: Option<DateTime<Utc>>,
        /// Sort by: created_at (default), entity, entity_name, operation
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,
        /// Sort order: desc (default) or asc
        #[arg(long, value_name = "asc|desc")]
        order: Option<String>,
        /// Maximum number of rows to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of rows to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `audit` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: AuditCommand) -> Result<(), CliError> {
    match subcommand {
        AuditCommand::List {
            entity,
            name,
            since,
            until,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<AuditLogResponse>>(
                DaemonCommand::ListAuditLogs(AuditLogFilter {
                    entity,
                    entity_name: name,
                    since,
                    until,
                    sort,
                    order,
                    limit,
                    offset,
                }),
            )
            .await?;
            log::debug!("Audit list result: {:?}", response);
            output::print_page(&response.data, output, |item| AuditLogRow::from(item))?;
        }
    }

    Ok(())
}
