use bindizr_service::types::{AccessLogResponse, AuditLogResponse, TransferLogResponse};
use tabled::Tabled;

use crate::cli::output::display;

/// One transfer Bindizr answered, refused, or failed, as `log transfer` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TransferLogRow {
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "TRANSFER")]
    pub(crate) transfer: String,
    #[tabled(rename = "TRANSPORT")]
    pub(crate) transport: String,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: String,
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "AT")]
    pub(crate) at: String,
    #[tabled(rename = "ERROR")]
    pub(crate) error: String,
}

impl From<&TransferLogResponse> for TransferLogRow {
    /// Build a CLI table row from one served transfer.
    fn from(transfer: &TransferLogResponse) -> Self {
        Self {
            zone_name: transfer.zone_name.clone(),
            transfer: display::display_transfer_kind(transfer),
            transport: transfer.transport.to_string(),
            serial: display::display_option(&transfer.serial),
            address: transfer.address.clone(),
            at: display::display_time(transfer.at),
            error: display::display_option(&transfer.error),
        }
    }
}

/// One request a front end answered, as `log access` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct AccessLogRow {
    #[tabled(rename = "AT")]
    pub(crate) at: String,
    #[tabled(rename = "SOURCE")]
    pub(crate) source: String,
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "REQUEST")]
    pub(crate) request: String,
    #[tabled(rename = "STATUS")]
    pub(crate) status: String,
    #[tabled(rename = "RESULT")]
    pub(crate) result: String,
    #[tabled(rename = "CALLER")]
    pub(crate) caller: String,
    #[tabled(rename = "ERROR")]
    pub(crate) error: String,
}

impl From<&AccessLogResponse> for AccessLogRow {
    /// Build a CLI table row from one access log row.
    fn from(log: &AccessLogResponse) -> Self {
        Self {
            at: display::display_time(log.requested_at),
            source: log.source.to_string(),
            address: log.address.clone(),
            request: display::display_access_request(log),
            status: log.status.clone(),
            result: log.result.to_string(),
            caller: display::display_option(&log.caller),
            error: display::display_option(&log.error),
        }
    }
}

/// One management change, as `log audit` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct AuditLogRow {
    #[tabled(rename = "AT")]
    pub(crate) at: String,
    #[tabled(rename = "ENTITY")]
    pub(crate) entity: String,
    #[tabled(rename = "NAME")]
    pub(crate) entity_name: String,
    #[tabled(rename = "OPERATION")]
    pub(crate) operation: String,
    #[tabled(rename = "SOURCE")]
    pub(crate) change_source: String,
    #[tabled(rename = "CHANGED BY")]
    pub(crate) changed_by: String,
    #[tabled(rename = "DETAIL")]
    pub(crate) detail: String,
}

impl From<&AuditLogResponse> for AuditLogRow {
    /// Build a CLI table row from one audit log row.
    fn from(log: &AuditLogResponse) -> Self {
        Self {
            at: display::display_time(log.created_at),
            entity: log.entity.to_string(),
            entity_name: log.entity_name.clone(),
            operation: log.operation.to_string(),
            change_source: log.change_source.to_string(),
            changed_by: display::display_option(&log.changed_by),
            detail: display::display_option(&log.detail),
        }
    }
}
