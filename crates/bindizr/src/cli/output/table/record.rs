use bindizr_core::dns::Ttl;
use bindizr_core::model::record::RecordId;
use bindizr_core::model::zone::ZoneId;
use bindizr_service::types::RecordResponse;
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct RecordRow {
    #[tabled(rename = "ID", display = "display::display_option")]
    pub(crate) id: Option<RecordId>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: Ttl,
    #[tabled(rename = "PRIORITY", display = "display::display_option")]
    pub(crate) priority: Option<i32>,
    #[tabled(rename = "ZONE-ID")]
    pub(crate) zone_id: ZoneId,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
}

impl RecordRow {
    /// Build the row for a single record, whose whole value is the point.
    pub(crate) fn whole(record: &RecordResponse) -> Self {
        Self::with_value(record, record.value.to_string())
    }

    /// Assemble a row with the value rendered for the current table.
    fn with_value(record: &RecordResponse, value: String) -> Self {
        Self {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.to_string(),
            value,
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: record.zone_name.clone(),
        }
    }
}

impl From<&RecordResponse> for RecordRow {
    /// Build a CLI table row from the record response, with the value shortened
    /// so one long record does not widen the column.
    fn from(record: &RecordResponse) -> Self {
        Self::with_value(record, display::display_record_value(&record.value))
    }
}
