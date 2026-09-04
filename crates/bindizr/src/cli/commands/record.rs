use bindizr_service::types::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, GetRecordResponse,
    GetRecordsFilter, RecordItem, RecordValueRequest, UpdateRecordPatch,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            ItemOrPage, OutputFormat, RecordRow, parse_response, print_response,
            render_change_preview,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{BulkCreateRecordsParams, DaemonCommandKind, RecordIdParams, UpdateRecordParams},
    },
};

/// Subcommands for managing records.
#[derive(Subcommand, Debug)]
pub(crate) enum RecordCommand {
    /// Create a record
    Create {
        /// Record name
        #[arg(long)]
        name: String,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(long = "type", alias = "record-type")]
        record_type: String,
        /// Record value
        #[arg(long)]
        value: String,
        /// Zone name
        #[arg(short, long)]
        zone: String,
        /// TTL in seconds, defaulting to the zone TTL (records of one RRset share a TTL)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority (MX and SRV only)
        #[arg(long)]
        priority: Option<i32>,
    },

    /// Bulk insert records into a zone from a JSON or YAML file
    #[command(after_help = "\
Input format (JSON or YAML): an array of records, or an object with a
'records' array. Fields per record:
  name         owner name relative to the zone, or '@' for the apex (required)
  record_type  A, AAAA, CNAME, MX, NS, PTR, SRV, TXT (required)
  value        record value; TXT also accepts an array of strings (required)
  ttl          seconds (optional; defaults to the zone TTL)
  priority     MX/SRV priority (optional)

JSON example:
  [{\"name\": \"www\", \"record_type\": \"A\", \"value\": \"192.0.2.1\", \"ttl\": 300},
   {\"name\": \"@\", \"record_type\": \"MX\", \"value\": \"mail\", \"priority\": 10}]

YAML example:
  - name: www
    record_type: A
    value: 192.0.2.1
    ttl: 300")]
    BulkCreate {
        /// Path to a JSON or YAML file (an array of records, or an object with
        /// a 'records' array), or '-' to read from stdin
        file: String,
        /// Zone name
        #[arg(short, long)]
        zone: String,
        /// Parse and validate without applying any change
        #[arg(long)]
        dry_run: bool,
        /// Preview the inserts as a +/-/~ diff without applying them (implies --dry-run)
        #[arg(long)]
        preview: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// List records
    #[command(alias = "ls")]
    List {
        /// Filter by zone name
        #[arg(short, long)]
        zone: Option<String>,
        /// Filter by record name
        #[arg(long)]
        name: Option<String>,
        /// Filter by record type
        #[arg(long = "type", alias = "record-type")]
        record_type: Option<String>,
        /// Filter by record value
        #[arg(long)]
        value: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i32>,
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i32>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i32>,
        /// Filter by priority
        #[arg(long)]
        priority: Option<i32>,
        /// Filter by minimum priority
        #[arg(long)]
        min_priority: Option<i32>,
        /// Filter by maximum priority
        #[arg(long)]
        max_priority: Option<i32>,
        /// Search records by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
        /// Append the derived DNSSEC records (RRSIG, DNSKEY, NSEC, ...)
        #[arg(long)]
        signed: bool,
        /// Maximum number of records to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of records to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get a record by ID
    Get {
        /// The record ID
        id: i32,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Update a record, changing only the fields you pass
    Update {
        /// The record ID
        id: i32,
        /// Record name
        #[arg(long)]
        name: Option<String>,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(long = "type", alias = "record-type")]
        record_type: Option<String>,
        /// Record value
        #[arg(long)]
        value: Option<String>,
        /// TTL (records of one RRset share a TTL)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority (MX and SRV only)
        #[arg(long)]
        priority: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Delete a record
    #[command(alias = "rm")]
    Delete {
        /// The record ID
        record_id: i32,
    },
}

/// Handle the `record` subcommand by forwarding it to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: RecordCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        RecordCommand::Create {
            name,
            record_type,
            value,
            zone,
            ttl,
            priority,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::CreateRecord,
                    CreateRecordRequest {
                        name,
                        record_type,
                        value: RecordValueRequest::String(value),
                        zone_name: zone,
                        ttl,
                        priority,
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        RecordCommand::List {
            zone,
            name,
            record_type,
            value,
            ttl,
            min_ttl,
            max_ttl,
            priority,
            min_priority,
            max_priority,
            search,
            signed,
            limit,
            offset,
            output,
        } => {
            let has_filters = zone.is_some()
                || name.is_some()
                || record_type.is_some()
                || value.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || priority.is_some()
                || min_priority.is_some()
                || max_priority.is_some()
                || search.is_some()
                || signed
                || limit.is_some()
                || offset.is_some();
            let filter = has_filters.then_some(GetRecordsFilter {
                zone_name: zone,
                name,
                record_type,
                value,
                ttl,
                min_ttl,
                max_ttl,
                priority,
                min_priority,
                max_priority,
                search,
                signed: signed.then_some(true),
                limit,
                offset,
            });
            let data = client
                .send_command(DaemonCommandKind::ListRecords, filter)
                .await?
                .data;

            print_records(&data, output)?;
        }
        RecordCommand::BulkCreate {
            file,
            zone,
            dry_run,
            preview,
            output,
        } => {
            let content = super::read_input(&file)?;
            // YAML is a superset of JSON, so one parse accepts both formats.
            let parsed: serde_json::Value = serde_yaml::from_str(&content)
                .map_err(|e| format!("Invalid JSON/YAML in '{}': {}", file, e))?;
            let records = match parsed {
                serde_json::Value::Array(_) => parsed,
                serde_json::Value::Object(mut obj) => obj
                    .remove("records")
                    .ok_or("Input object must contain a 'records' array")?,
                _ => {
                    return Err(
                        "Expected an array of records or an object with a 'records' array".into(),
                    );
                }
            };
            let records: Vec<RecordItem> = serde_json::from_value(records)
                .map_err(|e| format!("Invalid record in '{}': {}", file, e))?;

            let response = client
                .send_command(
                    DaemonCommandKind::BulkCreateRecords,
                    BulkCreateRecordsParams {
                        zone_name: zone,
                        request: CreateBulkRecordsRequest {
                            records,
                            // Preview never applies; it is a dry run rendered as a diff.
                            dry_run: dry_run || preview,
                        },
                    },
                )
                .await?;

            if preview && output == OutputFormat::Table {
                let bulk: BulkRecordsResponse = parse_response(&response.data)?;
                print!("{}", render_change_preview(&bulk.diff.entries));
                return Ok(());
            }

            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_response(&response.data, output, |bulk: &BulkRecordsResponse| {
                bulk.records.iter().map(RecordRow::from).collect()
            })?;
        }
        RecordCommand::Get { id, output } => {
            let data = client
                .send_command(DaemonCommandKind::GetRecord, RecordIdParams { id })
                .await?
                .data;

            print_records(&data, output)?;
        }
        RecordCommand::Update {
            id,
            name,
            record_type,
            value,
            ttl,
            priority,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::UpdateRecord,
                    UpdateRecordParams {
                        id,
                        patch: UpdateRecordPatch {
                            name,
                            record_type,
                            value: value.map(RecordValueRequest::String),
                            ttl,
                            priority,
                        },
                    },
                )
                .await?
                .data;

            print_records(&data, output)?;
        }
        RecordCommand::Delete { record_id } => {
            let response = client
                .send_command(
                    DaemonCommandKind::DeleteRecord,
                    RecordIdParams { id: record_id },
                )
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}

fn print_records(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |records: &ItemOrPage<GetRecordResponse>| {
        records.items().iter().map(RecordRow::from).collect()
    })
}
