/// The table a retention pass pruned rows from, as the pruned-rows counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrunedTable {
    Journal,
    Version,
    Audit,
    Access,
    Transfer,
}

impl PrunedTable {
    pub(crate) const ALL: [Self; 5] = [
        Self::Journal,
        Self::Version,
        Self::Audit,
        Self::Access,
        Self::Transfer,
    ];

    /// Return the canonical text representation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Journal => "journal",
            Self::Version => "version",
            Self::Audit => "audit",
            Self::Access => "access",
            Self::Transfer => "transfer",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics;

    /// Verify that canonical spellings remain stable in the Prometheus exposition.
    #[test]
    fn pruned_table_spells_itself_once() {
        let spellings = PrunedTable::ALL.map(PrunedTable::as_str);
        assert_eq!(
            spellings,
            ["journal", "version", "audit", "access", "transfer"]
        );

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_pruned_rows_total", "table"),
            expected
        );
    }
}
