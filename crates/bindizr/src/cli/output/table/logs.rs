use bindizr_core::model::activity_log::ActivityLog;
use bindizr_core::model::transfer::TransferResult;
use bindizr_service::types::{AccessLogResponse, TransferLogResponse};
use tabled::Tabled;

use crate::cli::output::display;

/// One transfer Bindizr answered, refused, or failed, as `log transfer` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TransferLogRow {
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "TRANSFER TYPE")]
    pub(crate) kind: String,
    #[tabled(rename = "RESPONSE")]
    pub(crate) response: &'static str,
    #[tabled(rename = "RESULT")]
    pub(crate) result: String,
    #[tabled(rename = "TRANSPORT")]
    pub(crate) transport: String,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: String,
    #[tabled(rename = "CLIENT IP")]
    pub(crate) client_ip: String,
    #[tabled(rename = "AT")]
    pub(crate) created_at: String,
    #[tabled(rename = "ERROR CODE")]
    pub(crate) error_code: String,
}

impl From<&TransferLogResponse> for TransferLogRow {
    /// Build a CLI table row from one transfer log entry.
    fn from(transfer: &TransferLogResponse) -> Self {
        Self {
            zone_name: transfer.zone_name.clone(),
            kind: transfer.kind.to_string(),
            response: match (transfer.result, transfer.incremental) {
                (TransferResult::Ok, true) => "delta",
                (TransferResult::Ok, false) => "full",
                _ => display::MISSING_CELL,
            },
            result: transfer.result.to_string(),
            transport: transfer.transport.to_string(),
            serial: display::display_option(&transfer.serial),
            client_ip: transfer.client_ip.clone(),
            created_at: display::display_time(transfer.created_at),
            error_code: display::display_option(&transfer.error_code),
        }
    }
}

/// One request a front end answered, as `log access` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct AccessLogRow {
    #[tabled(rename = "AT")]
    pub(crate) requested_at: String,
    #[tabled(rename = "SOURCE")]
    pub(crate) source: String,
    #[tabled(rename = "CLIENT IP")]
    pub(crate) client_ip: String,
    #[tabled(rename = "REQUEST")]
    pub(crate) request: String,
    #[tabled(rename = "RESPONSE CODE")]
    pub(crate) response_code: String,
    #[tabled(rename = "RESULT")]
    pub(crate) result: String,
    #[tabled(rename = "ACTOR")]
    pub(crate) actor: String,
    #[tabled(rename = "ERROR CODE")]
    pub(crate) error_code: String,
}

impl From<&AccessLogResponse> for AccessLogRow {
    /// Build a CLI table row from one access log row.
    fn from(log: &AccessLogResponse) -> Self {
        Self {
            requested_at: display::display_time(log.requested_at),
            source: log.source.to_string(),
            client_ip: log.client_ip.clone(),
            request: display::display_access_request(log),
            response_code: log.response_code.clone(),
            result: log.result.to_string(),
            actor: display::display_option(&log.actor),
            error_code: display::display_option(&log.error_code),
        }
    }
}

/// One recorded activity log entry, as `log activity` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ActivityLogRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i64,
    #[tabled(rename = "AT")]
    pub(crate) created_at: String,
    #[tabled(rename = "OPERATION")]
    pub(crate) operation: String,
    #[tabled(rename = "TARGET")]
    pub(crate) target: String,
    #[tabled(rename = "SOURCE")]
    pub(crate) source: String,
    #[tabled(rename = "ACTOR")]
    pub(crate) actor: String,
    #[tabled(rename = "RESULT")]
    pub(crate) result: String,
    #[tabled(rename = "DETAIL")]
    pub(crate) detail: String,
}

impl From<&ActivityLog> for ActivityLogRow {
    /// Build a CLI table row from one recorded operation.
    fn from(log: &ActivityLog) -> Self {
        Self {
            id: log.id,
            created_at: display::display_time(log.created_at),
            operation: log.operation.to_string(),
            target: display::display_activity_target(&log.target),
            source: log.source.to_string(),
            actor: display::display_option(&log.actor),
            result: log.result.to_string(),
            detail: display::display_option(&log.detail),
        }
    }
}
