//! Which stored records a request names, when it narrows by type, value
//! and preference rather than by row id.

use crate::model::record::{Record, RecordType};

/// Whether a stored record falls inside the narrowing RFC 2136, Section 2.5.2
/// spells for a delete: the type, then the rdata, then the preference. Values
/// compare canonically and without the priority, which MX and SRV keep in
/// their own column and which narrows separately.
pub(crate) fn matches_record(
    record: &Record,
    record_type: Option<&RecordType>,
    value: Option<&str>,
    priority: Option<i32>,
) -> bool {
    if record_type.is_some_and(|wanted| *wanted != record.record_type) {
        return false;
    }
    if value.is_some_and(|value| {
        !record
            .record_type
            .values_equal(&record.value, None, value, None)
    }) {
        return false;
    }

    priority.is_none_or(|wanted| record.priority == Some(wanted))
}

#[cfg(test)]
mod tests;
