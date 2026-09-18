use bindizr_core::{out, outln};
use bindizr_service::types::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsFilter,
    GetRecordResponse, GetRecordsFilter, PaginatedResponse, RecordItem, RecordResponse,
    RecordValueRequest, UpdateRecordRequest,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            OutputFormat, RecordRow, parse_response, print_payload, print_response, print_table,
            render_change_preview,
        },
    },
    socket::{
        client,
        types::{DaemonCommandKind, RecordIdParams, UpdateRecordByNameParams, UpdateRecordParams},
    },
};

/// Subcommands for managing records.
#[derive(Subcommand, Debug)]
pub(crate) enum RecordCommand {
    /// Create a record
    #[command(after_help = "\
Examples:
  bindizr record create example.com www --type A --value 192.0.2.1
  bindizr record create example.com @ --type MX --priority 10 --value mail.example.com
  bindizr record create example.com @ --type TXT --value \"v=spf1 include:_spf.example.net ~all\"

A TXT value longer than 255 bytes is split for you. Repeat --value only to
choose the split yourself, as a DKIM key's publisher does; resolvers join the
parts with nothing between them, so a space has to be inside a value.")]
    Create {
        /// Zone the record belongs to
        #[arg(value_name = "ZONE_NAME")]
        zone: String,
        /// Owner name relative to the zone, or '@' for the apex
        #[arg(value_name = "RECORD_NAME")]
        name: String,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(long = "type")]
        record_type: String,
        /// Record value; repeat it to choose a long TXT value's segments yourself
        #[arg(long, value_name = "VALUE", action = clap::ArgAction::Append, required = true)]
        value: Vec<String>,
        /// TTL in seconds, defaulting to the zone TTL (records sharing a name and type share one TTL)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority, MX and SRV only (default: 10)
        #[arg(long)]
        priority: Option<i32>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Bulk insert records into a zone from a JSON or YAML file
    #[command(after_help = "\
Input format (JSON or YAML): an array of records, or an object with a
'records' array. Fields per record:
  name      owner name relative to the zone, or '@' for the apex (required)
  type      A, AAAA, CAA, CNAME, DNAME, DS, MX, NAPTR, NS, PTR, SRV, SSHFP,
            TLSA, TXT (required)
  value     record value; TXT also accepts an array of strings (required)
  ttl       seconds (optional; defaults to the zone TTL)
  priority  MX/SRV priority (optional; defaults to 10)

JSON example:
  [{\"name\": \"www\", \"type\": \"A\", \"value\": \"192.0.2.1\", \"ttl\": 300},
   {\"name\": \"@\", \"type\": \"MX\", \"value\": \"mail\", \"priority\": 10}]

YAML example:
  - name: www
    type: A
    value: 192.0.2.1
    ttl: 300")]
    BulkCreate {
        /// Zone the records belong to
        #[arg(value_name = "ZONE_NAME")]
        zone: String,
        /// Path to a JSON or YAML file (an array of records, or an object with
        /// a 'records' array), or '-' to read from stdin
        file: String,
        /// Parse and validate without applying any change, showing the inserts
        /// as a +/-/~ diff
        #[arg(long)]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// List records
    #[command(
        alias = "ls",
        after_help = "\
Examples:
  bindizr record list example.com
  bindizr record list example.com --type A --sort ttl --order desc
  bindizr record list --name www

Omit the zone to list records from every zone the caller can see."
    )]
    List {
        /// Zone to list; omitted, records from every visible zone are listed
        #[arg(value_name = "ZONE_NAME")]
        zone: Option<String>,
        /// Filter by record name
        #[arg(long, value_name = "RECORD_NAME")]
        name: Option<String>,
        /// Filter by record type
        #[arg(long = "type")]
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
        /// Sort by: name (default), record_type, ttl, priority, created_at
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,
        /// Sort order: asc (default) or desc
        #[arg(long, value_name = "asc|desc")]
        order: Option<String>,
        /// Append the derived DNSSEC records (RRSIG, DNSKEY, NSEC, ...)
        #[arg(long)]
        signed: bool,
        /// Maximum number of records to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of records to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Get every record at a name, or one record by ID
    #[command(after_help = "\
Examples:
  bindizr record get example.com www
  bindizr record get --id 42

A name can hold several records, so the name form lists all of them. --id
addresses exactly one.")]
    Get {
        /// Zone the records belong to
        #[arg(
            value_name = "ZONE_NAME",
            required_unless_present = "id",
            requires = "name"
        )]
        zone: Option<String>,
        /// Owner name relative to the zone, or '@' for the apex
        #[arg(
            value_name = "RECORD_NAME",
            required_unless_present = "id",
            requires = "zone"
        )]
        name: Option<String>,
        /// The record ID; addresses exactly one record
        #[arg(long, value_name = "RECORD_ID", conflicts_with = "name")]
        id: Option<i32>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Update a record, changing only the fields you pass
    #[command(after_help = "\
Examples:
  bindizr record update example.com www --value 192.0.2.2
  bindizr record update example.com www --new-name api
  bindizr record update --id 42 --type TXT --value \"hello\"

Every flag below sets a new value; none of them picks which record to change.
The name form therefore changes the one record at the name and reports an
error when the name holds several, which --id then addresses individually.")]
    Update {
        /// Zone the record belongs to
        #[arg(
            value_name = "ZONE_NAME",
            required_unless_present = "id",
            requires = "name"
        )]
        zone: Option<String>,
        /// Owner name relative to the zone, or '@' for the apex; holding
        /// several records there is an error
        #[arg(
            value_name = "RECORD_NAME",
            required_unless_present = "id",
            requires = "zone"
        )]
        name: Option<String>,
        /// The record ID; addresses exactly one record
        #[arg(long, value_name = "RECORD_ID", conflicts_with = "name")]
        id: Option<i32>,
        /// Move the record to this owner name
        #[arg(long, value_name = "RECORD_NAME")]
        new_name: Option<String>,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(long = "type")]
        record_type: Option<String>,
        /// Record value; repeat it for the segments of a TXT record
        #[arg(long, value_name = "VALUE", action = clap::ArgAction::Append)]
        value: Vec<String>,
        /// TTL (records sharing a name and type share one TTL)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority (MX and SRV only)
        #[arg(long)]
        priority: Option<i32>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Delete one record by ID, or every record at a name
    #[command(
        alias = "rm",
        after_help = "\
Examples:
  bindizr record delete example.com www
  bindizr record delete example.com www --type A --dry-run
  bindizr record delete --id 42

Deleting by name narrows as RFC 2136, Section 2.5.2 does:
  name only                   every record type at the name
  name --type                 every record of that type at the name
  name --type --value         one record

The whole set goes in one transaction, so the zone advances by a single
serial and the secondaries transfer once."
    )]
    Delete {
        /// Zone the records belong to
        #[arg(
            value_name = "ZONE_NAME",
            required_unless_present = "id",
            requires = "name"
        )]
        zone: Option<String>,
        /// Owner name relative to the zone, or '@' for the apex; every record
        /// there goes unless a flag below narrows it
        #[arg(
            value_name = "RECORD_NAME",
            required_unless_present = "id",
            requires = "zone"
        )]
        name: Option<String>,
        /// The record ID; deletes exactly that one record
        #[arg(long, value_name = "RECORD_ID", conflicts_with = "name")]
        id: Option<i32>,
        /// Narrow to one record type
        #[arg(long = "type", requires = "name")]
        record_type: Option<String>,
        /// Narrow to one value (requires --type)
        #[arg(long, requires = "record_type")]
        value: Option<String>,
        /// Narrow to one MX/SRV priority
        #[arg(long, requires = "name")]
        priority: Option<i32>,
        /// Report what would go without removing anything
        #[arg(long, requires = "name")]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `record` subcommand by forwarding it to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: RecordCommand) -> Result<(), CliError> {
    match subcommand {
        RecordCommand::Create {
            name,
            record_type,
            value,
            zone,
            ttl,
            priority,
            output,
        } => {
            let data = client::send_command(
                DaemonCommandKind::CreateRecord,
                CreateRecordRequest {
                    name,
                    record_type,
                    value: to_record_value_request(value),
                    zone_name: zone,
                    ttl,
                    priority,
                },
            )
            .await?
            .data;

            print_response(&data, output, |response: &RecordResponse| {
                vec![RecordRow::from(&response.record)]
            })?;
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
            sort,
            order,
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
                || sort.is_some()
                || order.is_some()
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
                sort,
                order,
                limit,
                offset,
            });
            let data = client::send_command(DaemonCommandKind::ListRecords, filter)
                .await?
                .data;

            print_response(
                &data,
                output,
                |page: &PaginatedResponse<GetRecordResponse>| {
                    page.items.iter().map(RecordRow::from).collect()
                },
            )?;
        }
        RecordCommand::BulkCreate {
            file,
            zone,
            dry_run,
            output,
        } => {
            let content = super::read_input(&file)?;
            // YAML is a superset of JSON, so one parse accepts both formats.
            let parsed: serde_json::Value = serde_norway::from_str(&content)
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

            let response = client::send_command(
                DaemonCommandKind::CreateRecordsBulk,
                CreateBulkRecordsRequest {
                    zone_name: zone,
                    records,
                    dry_run,
                },
            )
            .await?;

            match output {
                OutputFormat::Table => {
                    let bulk: BulkRecordsResponse = parse_response(&response.data)?;
                    outln!("{}", response.message);
                    if dry_run {
                        out!("{}", render_change_preview(&bulk.diff));
                    } else {
                        print_table(bulk.records.iter().map(RecordRow::from).collect());
                    }
                }
                _ => print_payload(&response.data, output)?,
            }
        }
        // clap holds the two selectors apart.
        RecordCommand::Get {
            id: Some(id),
            output,
            ..
        } => {
            let data = client::send_command(DaemonCommandKind::GetRecord, RecordIdParams { id })
                .await?
                .data;

            print_response(&data, output, |response: &RecordResponse| {
                vec![RecordRow::whole(&response.record)]
            })?;
        }
        RecordCommand::Get {
            name: Some(name),
            zone,
            output,
            ..
        } => {
            // A name can hold several records, so this is the listing filtered
            // to one owner rather than a single-record lookup.
            let data = client::send_command(
                DaemonCommandKind::ListRecords,
                GetRecordsFilter {
                    zone_name: zone,
                    name: Some(name),
                    ..GetRecordsFilter::default()
                },
            )
            .await?
            .data;

            print_response(
                &data,
                output,
                |page: &PaginatedResponse<GetRecordResponse>| {
                    page.items.iter().map(RecordRow::whole).collect()
                },
            )?;
        }
        RecordCommand::Get { .. } => {
            return Err(CliError::from(
                "give a zone and a record name, or --id to address one record",
            ));
        }
        RecordCommand::Update {
            id: Some(id),
            new_name,
            record_type,
            value,
            ttl,
            priority,
            output,
            ..
        } => {
            let data = client::send_command(
                DaemonCommandKind::UpdateRecord,
                UpdateRecordParams {
                    id,
                    request: UpdateRecordRequest {
                        name: new_name,
                        record_type,
                        value: (!value.is_empty()).then(|| to_record_value_request(value)),
                        ttl,
                        priority,
                    },
                },
            )
            .await?
            .data;

            print_response(&data, output, |response: &RecordResponse| {
                vec![RecordRow::from(&response.record)]
            })?;
        }
        RecordCommand::Update {
            name: Some(name),
            zone: Some(zone),
            new_name,
            record_type,
            value,
            ttl,
            priority,
            output,
            ..
        } => {
            let data = client::send_command(
                DaemonCommandKind::UpdateRecordByName,
                UpdateRecordByNameParams {
                    zone_name: zone,
                    name,
                    request: UpdateRecordRequest {
                        name: new_name,
                        record_type,
                        value: (!value.is_empty()).then(|| to_record_value_request(value)),
                        ttl,
                        priority,
                    },
                },
            )
            .await?
            .data;

            print_response(&data, output, |response: &RecordResponse| {
                vec![RecordRow::from(&response.record)]
            })?;
        }
        RecordCommand::Update { .. } => {
            return Err(CliError::from(
                "give a zone and a record name, or --id to address one record",
            ));
        }
        RecordCommand::Delete {
            id: Some(id),
            output,
            ..
        } => {
            let response =
                client::send_command(DaemonCommandKind::DeleteRecord, RecordIdParams { id })
                    .await?;
            match output {
                OutputFormat::Table => outln!("{}", response.message),
                _ => print_payload(&response.data, output)?,
            }
        }
        RecordCommand::Delete {
            zone: Some(zone),
            name: Some(name),
            record_type,
            value,
            priority,
            dry_run,
            output,
            ..
        } => {
            let response = client::send_command(
                DaemonCommandKind::DeleteRecordsMatching,
                DeleteRecordsFilter {
                    zone_name: zone,
                    name,
                    record_type,
                    value,
                    priority,
                    dry_run,
                },
            )
            .await?;
            match output {
                OutputFormat::Table => outln!("{}", response.message),
                _ => print_payload(&response.data, output)?,
            }
        }
        RecordCommand::Delete { .. } => {
            return Err(CliError::from(
                "give a zone and a record name, or --id to delete one record",
            ));
        }
    }

    Ok(())
}

/// One `--value` is the record's value; several are the segments of a TXT
/// record.
fn to_record_value_request(mut values: Vec<String>) -> RecordValueRequest {
    if values.len() == 1 {
        RecordValueRequest::String(values.remove(0))
    } else {
        RecordValueRequest::Segments(values)
    }
}
