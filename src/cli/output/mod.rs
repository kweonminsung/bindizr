pub mod format;
pub mod table;

pub use format::{OutputFormat, print_output_with_table};
pub use table::{DnsRow, KeyRow, RecordRow, ZoneRow};
