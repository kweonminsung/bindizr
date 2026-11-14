//! What a listing sorts by, as a closed vocabulary: the query renders its
//! `ORDER BY` from these, so no caller text reaches the SQL.

use std::str::FromStr;

use thiserror::Error;

/// A sort parameter a listing did not recognise.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneSortField {
    #[default]
    Name,
    Serial,
    DefaultTtl,
    CreatedAt,
}

impl ZoneSortField {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Serial => "serial",
            Self::DefaultTtl => "default_ttl",
            Self::CreatedAt => "created_at",
        }
    }

    /// Build a zone listing order with id as the tie-breaker, preventing tied
    /// rows from moving between pages.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, id", self.column(), order.as_str())
    }
}

impl FromStr for ZoneSortField {
    type Err = ParseSortError;

    /// Parse a zone sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(Self::Name),
            "serial" => Ok(Self::Serial),
            "default_ttl" => Ok(Self::DefaultTtl),
            "created_at" => Ok(Self::CreatedAt),
            other => Err(ParseSortError::UnknownField {
                value: other.to_string(),
                expected: "name, serial, default_ttl, or created_at",
            }),
        }
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

    /// Return the `ORDER BY` a record listing pages under; see
    /// [`ZoneSortField::order_by_sql`].
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, r.id", self.column(), order.as_str())
    }
}

impl FromStr for RecordSortField {
    type Err = ParseSortError;

    /// Parse a record sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(Self::Name),
            "type" => Ok(Self::RecordType),
            "ttl" => Ok(Self::Ttl),
            "priority" => Ok(Self::Priority),
            "created_at" => Ok(Self::CreatedAt),
            other => Err(ParseSortError::UnknownField {
                value: other.to_string(),
                expected: "name, type, ttl, priority, or created_at",
            }),
        }
    }
}

/// The column an audit log listing sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLogSortField {
    #[default]
    CreatedAt,
    Entity,
    EntityName,
    Operation,
}

impl AuditLogSortField {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Entity => "entity",
            Self::EntityName => "entity_name",
            Self::Operation => "operation",
        }
    }

    /// Return the `ORDER BY` an audit listing pages under; the id tie-breaker
    /// follows the direction.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!(
            "ORDER BY {} {}, id {}",
            self.column(),
            order.as_str(),
            order.as_str(),
        )
    }
}

impl FromStr for AuditLogSortField {
    type Err = ParseSortError;

    /// Parse an audit sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "created_at" => Ok(Self::CreatedAt),
            "entity" => Ok(Self::Entity),
            "entity_name" => Ok(Self::EntityName),
            "operation" => Ok(Self::Operation),
            other => Err(ParseSortError::UnknownField {
                value: other.to_string(),
                expected: "created_at, entity, entity_name, or operation",
            }),
        }
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
    /// Return the canonical wire spelling.
    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

impl FromStr for SortOrder {
    type Err = ParseSortError;

    /// Parse a sort order from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "asc" => Ok(Self::Asc),
            "desc" => Ok(Self::Desc),
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
    fn order_by_appends_row_id_tiebreaker() {
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
        assert_eq!(
            AuditLogSortField::default().order_by_sql(SortOrder::Desc),
            "ORDER BY created_at DESC, id DESC"
        );
    }
}
