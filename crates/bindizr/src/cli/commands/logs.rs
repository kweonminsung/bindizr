use bindizr_core::model::activity_log::ActivityLog;
use bindizr_service::types::{
    AccessLogFilter, AccessLogResponse, ActivityLogFilter, PaginatedResponse, TransferLogFilter,
    TransferLogResponse,
};
use chrono::{DateTime, Utc};
use clap::Subcommand;

use crate::cli::error::CliError;
use crate::cli::output::{AccessLogRow, ActivityLogRow, OutputFormat, TransferLogRow};
use crate::cli::{output, time};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for reading the logs.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum LogCommand {
    /// List recorded changes and operation results, newest first
    #[command(after_help = "\
Examples:
  bindizr log activity
  bindizr log activity --entity token --name external-dns --result changed
  bindizr log activity --operation record.create --zone example.com --since 7d -o json
  bindizr log activity --record-name www --record-type A
  bindizr log activity --since 2026-10-01 --until 2026-11-01
  bindizr log activity --sort target --order asc

A time is a span ago (7d, 12h, 30m), a date (2026-10-01, midnight UTC as the
AT column is), or an RFC 3339 timestamp.")]
    Activity {
        /// The operation group, such as zone, record or secondary
        #[arg(long)]
        entity: Option<String>,
        /// A canonical operation name, such as zone.create
        #[arg(long)]
        operation: Option<String>,
        /// Filter by an activity result, such as changed
        #[arg(long)]
        result: Option<String>,
        /// Administrative target or zone name
        #[arg(long)]
        name: Option<String>,
        /// Zone associated with the operation
        #[arg(long)]
        zone: Option<String>,
        /// Record owner relative to its zone
        #[arg(long)]
        record_name: Option<String>,
        /// Record type mnemonic
        #[arg(long)]
        record_type: Option<String>,
        /// Only rows at or after this time
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only rows before this time
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        until: Option<DateTime<Utc>>,
        /// Sort by created_at (default), operation or target
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
    /// List the API requests and nsupdates answered, denied, or failed, newest first
    #[command(after_help = "\
Examples:
  bindizr log access
  bindizr log access --result denied --since 1d
  bindizr log access --actor external-dns
  bindizr log access --source nsupdate --client-ip 192.0.2.10 -o json

A time is a span ago (7d, 12h, 30m), a date (2026-10-01, midnight UTC as the
AT column is), or an RFC 3339 timestamp.

A management API request is logged with its method and path, an nsupdate with
its zone; each with the client address, the token or TSIG key that verified,
and the status or RCODE. denied is HTTP 401 or 403, or a TSIG rejection or
REFUSED. No query string, body, token or secret is kept. /health, /metrics,
the OpenAPI document and daemon socket commands are not logged.")]
    Access {
        /// Only requests that arrived here: api or nsupdate
        #[arg(long, value_name = "SOURCE")]
        source: Option<String>,
        /// Only requests that ended this way: ok, denied, or failed
        #[arg(long, value_name = "RESULT")]
        result: Option<String>,
        /// Only requests made with the token or TSIG key of this name
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
        /// Only requests from this client IP address
        #[arg(long, value_name = "IP")]
        client_ip: Option<String>,
        /// Only requests at or after this time: a span ago (7d, 12h, 30m), a
        /// UTC date (2026-10-01), or RFC 3339
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only requests before this time, in the same forms
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        until: Option<DateTime<Utc>>,
        /// Sort by: requested_at (default), source, target, response_code, result, client_ip
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
    /// List the zone transfers answered, refused, or failed, newest first
    #[command(after_help = "\
Examples:
  bindizr log transfer
  bindizr log transfer --secondary ns2 --since 1d
  bindizr log transfer --result refused
  bindizr log transfer --client-ip 192.0.2.10 --zone example.com -o json

A time is a span ago (7d, 12h, 30m), a date (2026-10-01, midnight UTC as the
AT column is), or an RFC 3339 timestamp.

A transfer is logged by client address and zone: AXFR, IXFR as a delta or the
whole zone, refused and why, or broken off by a failure. A transfer of a zone
Bindizr does not have leaves no row. --secondary selects the addresses the
secondary resolves to now.")]
    Transfer {
        /// Only transfers answered to the addresses this secondary resolves to
        #[arg(long, value_name = "NAME")]
        secondary: Option<String>,
        /// Only transfers answered to this client IP address
        #[arg(long, value_name = "IP")]
        client_ip: Option<String>,
        /// Only the transfers of this zone
        #[arg(long, value_name = "ZONE")]
        zone: Option<String>,
        /// Only transfers that turned out this way: ok, refused, or failed
        #[arg(long, value_name = "RESULT")]
        result: Option<String>,
        /// Only transfers recorded at or after this time: a span ago (7d, 12h, 30m), a
        /// UTC date (2026-10-01), or RFC 3339
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only transfers recorded before this time, in the same forms
        #[arg(long, value_name = "TIME", value_parser = time::parse_time)]
        until: Option<DateTime<Utc>>,
        /// Sort by: created_at (default), client_ip, zone_name, kind, result
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

/// Handle the `log` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: LogCommand) -> Result<(), CliError> {
    match subcommand {
        LogCommand::Activity {
            entity,
            operation,
            result,
            name,
            zone,
            record_name,
            record_type,
            since,
            until,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<ActivityLog>>(
                DaemonCommand::ListActivityLogs(ActivityLogFilter {
                    entity,
                    operation,
                    result,
                    name,
                    zone_name: zone,
                    record_name,
                    record_type,
                    since,
                    until,
                    sort,
                    order,
                    limit,
                    offset,
                }),
            )
            .await?;
            output::print_page(&response.data, output, |event| ActivityLogRow::from(event))?;
        }
        LogCommand::Access {
            source,
            result,
            actor,
            client_ip,
            since,
            until,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<AccessLogResponse>>(
                DaemonCommand::ListAccessLogs(AccessLogFilter {
                    source,
                    result,
                    actor_name: actor,
                    client_ip,
                    since,
                    until,
                    sort,
                    order,
                    limit,
                    offset,
                }),
            )
            .await?;
            output::print_page(&response.data, output, |log| AccessLogRow::from(log))?;
        }
        LogCommand::Transfer {
            secondary,
            client_ip,
            zone,
            result,
            since,
            until,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<TransferLogResponse>>(
                DaemonCommand::ListTransferLogs(TransferLogFilter {
                    secondary_name: secondary,
                    client_ip,
                    zone_name: zone,
                    result,
                    since,
                    until,
                    sort,
                    order,
                    limit,
                    offset,
                }),
            )
            .await?;
            output::print_page(&response.data, output, |log| TransferLogRow::from(log))?;
        }
    }

    Ok(())
}
