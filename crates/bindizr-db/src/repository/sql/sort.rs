//! What a listing sorts by, as a closed vocabulary: the query renders its
//! `ORDER BY` from these, so no caller text reaches the SQL.

/// The column a zone listing sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ZoneSort {
    #[default]
    Name,
    Serial,
    DefaultTtl,
    CreatedAt,
}

/// The column a record listing sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordSort {
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

impl ZoneSort {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            ZoneSort::Name => "name",
            ZoneSort::Serial => "serial",
            ZoneSort::DefaultTtl => "default_ttl",
            ZoneSort::CreatedAt => "created_at",
        }
    }

    /// The `ORDER BY` a zone listing pages under. The id follows the sort
    /// column so the order is total: rows tied on it would otherwise be free
    /// to swap between pages, dropping or repeating one.
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, id", self.column(), order.as_str())
    }
}

impl RecordSort {
    /// Return the SQL column for this sort field.
    fn column(self) -> &'static str {
        match self {
            RecordSort::Name => "r.name",
            RecordSort::RecordType => "r.record_type",
            RecordSort::Ttl => "r.ttl",
            RecordSort::Priority => "r.priority",
            RecordSort::CreatedAt => "r.created_at",
        }
    }

    /// The `ORDER BY` a record listing pages under; see
    /// [`ZoneSort::order_by_sql`].
    pub(crate) fn order_by_sql(self, order: SortOrder) -> String {
        format!("ORDER BY {} {}, r.id", self.column(), order.as_str())
    }
}

impl std::str::FromStr for ZoneSort {
    type Err = String;

    /// Parse a zone sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(ZoneSort::Name),
            "serial" => Ok(ZoneSort::Serial),
            "default_ttl" => Ok(ZoneSort::DefaultTtl),
            "created_at" => Ok(ZoneSort::CreatedAt),
            other => Err(format!(
                "unknown sort field '{other}': expected name, serial, default_ttl, or created_at"
            )),
        }
    }
}

impl std::str::FromStr for RecordSort {
    type Err = String;

    /// Parse a record sort from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "name" => Ok(RecordSort::Name),
            "record_type" => Ok(RecordSort::RecordType),
            "ttl" => Ok(RecordSort::Ttl),
            "priority" => Ok(RecordSort::Priority),
            "created_at" => Ok(RecordSort::CreatedAt),
            other => Err(format!(
                "unknown sort field '{other}': expected name, record_type, ttl, priority, or \
                 created_at"
            )),
        }
    }
}

impl std::str::FromStr for SortOrder {
    type Err = String;

    /// Parse a sort order from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "asc" => Ok(SortOrder::Asc),
            "desc" => Ok(SortOrder::Desc),
            other => Err(format!(
                "unknown sort order '{other}': expected asc or desc"
            )),
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
            ZoneSort::Serial.order_by_sql(SortOrder::Desc),
            "ORDER BY serial DESC, id"
        );
        assert_eq!(
            RecordSort::Ttl.order_by_sql(SortOrder::Asc),
            "ORDER BY r.ttl ASC, r.id"
        );
        assert_eq!(
            RecordSort::default().order_by_sql(SortOrder::default()),
            "ORDER BY r.name ASC, r.id"
        );
    }
}
