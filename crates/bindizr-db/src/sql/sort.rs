//! What a listing sorts by, as a closed vocabulary: the query renders its
//! `ORDER BY` from these, so no caller text reaches the SQL.

use std::str::FromStr;

use thiserror::Error;

/// A sort parameter a listing did not recognise.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseSortError {
    #[error("unknown sort field '{value}': expected {expected}")]
    UnknownField { value: String, expected: String },
    #[error("unknown sort order '{value}': expected {expected}")]
    UnknownOrder { value: String, expected: String },
}

/// Join a vocabulary as a sentence lists it: `a, b, or c`.
fn list_values(values: &[&str]) -> String {
    match values {
        [] => String::new(),
        [only] => (*only).to_string(),
        [first, second] => format!("{first} or {second}"),
        [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
    }
}

/// The column a zone listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneSortField {
    #[default]
    Name,
    Serial,
    DefaultTtl,
    CreatedAt,
}

impl ZoneSortField {
    /// Every field, in the order an error lists them.
    pub const ALL: [Self; 4] = [Self::Name, Self::Serial, Self::DefaultTtl, Self::CreatedAt];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Serial => "serial",
            Self::DefaultTtl => "default_ttl",
            Self::CreatedAt => "created_at",
        }
    }

    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Serial => "serial",
            Self::DefaultTtl => "default_ttl",
            Self::CreatedAt => "created_at",
        }
    }

    /// Return the `ORDER BY` a zone listing pages under. The row id breaks ties in
    /// the same direction, so tied rows neither move between pages nor read
    /// against the order asked for.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        let direction = order.keyword();

        format!("ORDER BY {} {direction}, id {direction}", self.column())
    }
}

impl FromStr for ZoneSortField {
    type Err = ParseSortError;

    /// Parse a zone sort from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownField {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

/// The column a record listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordSortField {
    #[default]
    Name,
    RecordType,
    Ttl,
    Priority,
    CreatedAt,
}

impl RecordSortField {
    /// Every field, in the order an error lists them.
    pub const ALL: [Self; 5] = [
        Self::Name,
        Self::RecordType,
        Self::Ttl,
        Self::Priority,
        Self::CreatedAt,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::RecordType => "type",
            Self::Ttl => "ttl",
            Self::Priority => "priority",
            Self::CreatedAt => "created_at",
        }
    }

    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::Name => "r.name",
            Self::RecordType => "r.record_type",
            Self::Ttl => "r.ttl",
            Self::Priority => "r.priority",
            Self::CreatedAt => "r.created_at",
        }
    }

    /// Return the `ORDER BY` a record listing pages under. The row id breaks ties in
    /// the same direction, so tied rows neither move between pages nor read
    /// against the order asked for.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        let direction = order.keyword();

        // Only priority is nullable, and backends place NULL apart: PostgreSQL
        // sorts it last ascending, MySQL and SQLite first. The NULL test leads,
        // so every backend puts it first ascending.
        if self == Self::Priority {
            return format!(
                "ORDER BY (r.priority IS NOT NULL) {direction}, r.priority {direction}, r.id {direction}"
            );
        }

        format!("ORDER BY {} {direction}, r.id {direction}", self.column())
    }
}

impl FromStr for RecordSortField {
    type Err = ParseSortError;

    /// Parse a record sort from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownField {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

/// The column a audit log listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLogSortField {
    #[default]
    CreatedAt,
    Entity,
    EntityName,
    Operation,
}

impl AuditLogSortField {
    /// Every field, in the order an error lists them.
    pub const ALL: [Self; 4] = [
        Self::CreatedAt,
        Self::Entity,
        Self::EntityName,
        Self::Operation,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Entity => "entity",
            Self::EntityName => "entity_name",
            Self::Operation => "operation",
        }
    }

    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Entity => "entity",
            Self::EntityName => "entity_name",
            Self::Operation => "operation",
        }
    }

    /// Return the `ORDER BY` a audit log listing pages under. The row id breaks ties in
    /// the same direction, so tied rows neither move between pages nor read
    /// against the order asked for.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        let direction = order.keyword();

        format!("ORDER BY {} {direction}, id {direction}", self.column())
    }
}

impl FromStr for AuditLogSortField {
    type Err = ParseSortError;

    /// Parse a audit log sort from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownField {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

/// The column a access log listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogSortField {
    #[default]
    RequestedAt,
    Source,
    Target,
    Status,
    Result,
    Address,
}

impl AccessLogSortField {
    /// Every field, in the order an error lists them.
    pub const ALL: [Self; 6] = [
        Self::RequestedAt,
        Self::Source,
        Self::Target,
        Self::Status,
        Self::Result,
        Self::Address,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestedAt => "requested_at",
            Self::Source => "source",
            Self::Target => "target",
            Self::Status => "status",
            Self::Result => "result",
            Self::Address => "address",
        }
    }

    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::RequestedAt => "requested_at",
            Self::Source => "source",
            Self::Target => "target",
            Self::Status => "status",
            Self::Result => "result",
            Self::Address => "client_addr",
        }
    }

    /// Return the `ORDER BY` a access log listing pages under. The row id breaks ties in
    /// the same direction, so tied rows neither move between pages nor read
    /// against the order asked for.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        let direction = order.keyword();

        format!("ORDER BY {} {direction}, id {direction}", self.column())
    }
}

impl FromStr for AccessLogSortField {
    type Err = ParseSortError;

    /// Parse a access log sort from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownField {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

/// The column a transfer log listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferLogSortField {
    #[default]
    At,
    Address,
    ZoneName,
    Kind,
    Result,
}

impl TransferLogSortField {
    /// Every field, in the order an error lists them.
    pub const ALL: [Self; 5] = [
        Self::At,
        Self::Address,
        Self::ZoneName,
        Self::Kind,
        Self::Result,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::At => "at",
            Self::Address => "address",
            Self::ZoneName => "zone_name",
            Self::Kind => "kind",
            Self::Result => "result",
        }
    }

    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::At => "t.served_at",
            Self::Address => "t.client_addr",
            Self::ZoneName => "z.name",
            Self::Kind => "t.kind",
            Self::Result => "t.result",
        }
    }

    /// Return the `ORDER BY` a transfer log listing pages under. The row id breaks ties in
    /// the same direction, so tied rows neither move between pages nor read
    /// against the order asked for.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        let direction = order.keyword();

        format!("ORDER BY {} {direction}, t.id {direction}", self.column())
    }
}

impl FromStr for TransferLogSortField {
    type Err = ParseSortError;

    /// Parse a transfer log sort from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownField {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

/// The direction a listing sorts its column in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

impl SortOrder {
    /// Every direction, in the order an error lists them.
    pub const ALL: [Self; 2] = [Self::Asc, Self::Desc];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    /// Return the SQL keyword for this direction.
    fn keyword(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

impl FromStr for SortOrder {
    type Err = ParseSortError;

    /// Parse a sort order from its text representation, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|order| order.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseSortError::UnknownOrder {
                value: value.to_string(),
                expected: list_values(&Self::ALL.map(Self::as_str)),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    /// Verify that an order by ends on the row id, in the sort's own direction.
    #[test]
    fn order_by_breaks_ties_by_id_in_the_same_direction() {
        // LIMIT/OFFSET over a non-unique sort would let tied rows swap between
        // pages, dropping or repeating one.
        assert_eq!(
            ZoneSortField::Serial.order_by_sql(SortOrder::Desc),
            "ORDER BY serial DESC, id DESC"
        );
        assert_eq!(
            RecordSortField::default().order_by_sql(SortOrder::default()),
            "ORDER BY r.name ASC, r.id ASC"
        );
        assert_eq!(
            AccessLogSortField::Address.order_by_sql(SortOrder::Asc),
            "ORDER BY client_addr ASC, id ASC"
        );
        assert_eq!(
            TransferLogSortField::default().order_by_sql(SortOrder::Desc),
            "ORDER BY t.served_at DESC, t.id DESC"
        );
    }

    /// Verify that every sort field and order parses from its `as_str`, in any case.
    #[test]
    fn sort_fields_spell_themselves_once() {
        /// Assert that each value reads back from its spelling, lower and upper case.
        fn assert_round_trip<T>(values: &[T], as_str: fn(T) -> &'static str)
        where
            T: Copy + PartialEq + fmt::Debug + FromStr<Err = ParseSortError>,
        {
            for value in values {
                let text = as_str(*value);

                assert_eq!(text.parse::<T>(), Ok(*value), "{text}");
                assert_eq!(text.to_ascii_uppercase().parse::<T>(), Ok(*value), "{text}");
            }
        }

        assert_round_trip(&ZoneSortField::ALL, ZoneSortField::as_str);
        assert_round_trip(&RecordSortField::ALL, RecordSortField::as_str);
        assert_round_trip(&AuditLogSortField::ALL, AuditLogSortField::as_str);
        assert_round_trip(&AccessLogSortField::ALL, AccessLogSortField::as_str);
        assert_round_trip(&TransferLogSortField::ALL, TransferLogSortField::as_str);
        assert_round_trip(&SortOrder::ALL, SortOrder::as_str);
    }

    /// Verify that a rejected sort lists the vocabulary it accepts.
    #[test]
    fn parse_rejects_unknown_values_listing_every_accepted_one() {
        assert_eq!(
            "method".parse::<ZoneSortField>().unwrap_err().to_string(),
            "unknown sort field 'method': expected name, serial, default_ttl, or created_at"
        );
        assert_eq!(
            "up".parse::<SortOrder>().unwrap_err().to_string(),
            "unknown sort order 'up': expected asc or desc"
        );
    }
}
