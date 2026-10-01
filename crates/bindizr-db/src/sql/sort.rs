//! What a listing sorts by, as a closed vocabulary: the query renders its
//! `ORDER BY` from these, so no caller text reaches the SQL.

use thiserror::Error;

/// A sort parameter a listing did not recognise.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseSortError {
    #[error("unknown sort field '{value}': expected {expected}")]
    UnknownField {
        value: String,
        expected: &'static str,
    },

    #[error("unknown sort order '{value}': expected asc or desc")]
    UnknownOrder { value: String },
}

/// The column a zone listing sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ZoneSortField {
    #[default]
    Name,
    Serial,
    DefaultTtl,
    CreatedAt,
}

/// The column a record listing sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordSortField {
    #[default]
    Name,
    RecordType,
    Ttl,
    Priority,
    CreatedAt,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

impl SortOrder {
    /// Return the text representation of this sort order.
    fn as_str(self) -> &'static str {
        match self {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        }
    }
}

impl ZoneSortField {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            ZoneSortField::Name => "name",
            ZoneSortField::Serial => "serial",
            ZoneSortField::DefaultTtl => "default_ttl",
            ZoneSortField::CreatedAt => "created_at",
        }
    }

    /// The `ORDER BY` a zone listing pages under. The id follows the sort
    /// column so the order is total: rows tied on it would otherwise be free
    /// to swap between pages, dropping or repeating one.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, id", self.column(), order.as_str())
    }
}

impl RecordSortField {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            RecordSortField::Name => "r.name",
            RecordSortField::RecordType => "r.record_type",
            RecordSortField::Ttl => "r.ttl",
            RecordSortField::Priority => "r.priority",
            RecordSortField::CreatedAt => "r.created_at",
        }
    }

    /// The `ORDER BY` a record listing pages under; see
    /// [`ZoneSortField::order_by_sql`].
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, r.id", self.column(), order.as_str())
    }
}

impl std::str::FromStr for ZoneSortField {
    type Err = ParseSortError;

    /// Parse a zone sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(ZoneSortField::Name),
            "serial" => Ok(ZoneSortField::Serial),
            "default_ttl" => Ok(ZoneSortField::DefaultTtl),
            "created_at" => Ok(ZoneSortField::CreatedAt),
            other => Err(ParseSortError::UnknownField {
                value: other.to_string(),
                expected: "name, serial, default_ttl, or created_at",
            }),
        }
    }
}

impl std::str::FromStr for RecordSortField {
    type Err = ParseSortError;

    /// Parse a record sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(RecordSortField::Name),
            "type" => Ok(RecordSortField::RecordType),
            "ttl" => Ok(RecordSortField::Ttl),
            "priority" => Ok(RecordSortField::Priority),
            "created_at" => Ok(RecordSortField::CreatedAt),
            other => Err(ParseSortError::UnknownField {
                value: other.to_string(),
                expected: "name, type, ttl, priority, or created_at",
            }),
        }
    }
}

impl std::str::FromStr for SortOrder {
    type Err = ParseSortError;

    /// Parse a sort order from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "asc" => Ok(SortOrder::Asc),
            "desc" => Ok(SortOrder::Desc),
            other => Err(ParseSortError::UnknownOrder {
                value: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that an order by always ends on the row id.
    #[test]
    fn an_order_by_always_ends_on_the_row_id() {
        // LIMIT/OFFSET over a non-unique sort would let tied rows swap between
        // pages, dropping or repeating one.
        assert_eq!(
            ZoneSortField::Serial.order_by_sql(SortOrder::Desc),
            "ORDER BY serial DESC, id"
        );
        assert_eq!(
            RecordSortField::Ttl.order_by_sql(SortOrder::Asc),
            "ORDER BY r.ttl ASC, r.id"
        );
        assert_eq!(
            RecordSortField::default().order_by_sql(SortOrder::default()),
            "ORDER BY r.name ASC, r.id"
        );
    }
}
