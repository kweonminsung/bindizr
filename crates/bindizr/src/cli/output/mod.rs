pub(crate) mod color;
mod diff;
mod format;
mod table;

pub(crate) use diff::{render_change_preview, render_diff_lines};
pub(crate) use format::{OutputFormat, parse_response, print_payload, print_response, print_table};
pub(crate) use table::{
    DnssecKeyRow, DnssecPolicyRow, ImportSummaryRow, RecordRow, RollbackSummaryRow, SecondaryRow,
    SecondaryStatusRow, TokenGrantRow, TokenRow, TsigGrantRow, TsigKeyRow, VersionRecordRow,
    VersionRow, ZoneRow,
};
