//! Outbound DNS question composition and response validation.

mod question;
mod response;

pub use question::{build_axfr_query, build_notify_query, build_question};
pub use response::{
    DsRecord, DsRecordSet, ParseResponseError, TransferMessagePosition, TransferRecord,
    extract_ds_record_set, extract_soa_serial, extract_tcp_keepalive_timeout,
    extract_transfer_records, is_truncated, matches_response_to_request, validate_notify_response,
};

#[cfg(test)]
mod tests;
