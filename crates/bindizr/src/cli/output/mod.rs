pub(crate) mod color;
pub(crate) mod diff;
pub(crate) mod format;
pub(crate) mod table;

pub(crate) use diff::{render_change_preview, render_diff_lines};
pub(crate) use format::{ItemOrPage, OutputFormat, parse_response, print_response, print_table};
pub(crate) use table::{
    DnssecKeyRow, DnssecPolicyRow, ImportSummaryRow, RecordRow, RollbackSummaryRow,
    SecondaryStatusRow, TokenRow, TsigKeyRow, VersionRecordRow, VersionRow, ZoneRow,
    ZoneTokenPolicyRow, ZoneTsigPolicyRow,
};
