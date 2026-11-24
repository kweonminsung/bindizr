/// The table a retention pass pruned rows from, as the pruned-rows counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrunedTable {
    Journal,
    Version,
    Activity,
    Access,
    Transfer,
}

impl PrunedTable {
    pub(crate) const ALL: [Self; 5] = [
        Self::Journal,
        Self::Version,
        Self::Activity,
        Self::Access,
        Self::Transfer,
    ];

    /// Return the canonical text representation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Journal => "zone_journal",
            Self::Version => "zone_versions",
            Self::Activity => "activity_log",
            Self::Access => "access_log",
            Self::Transfer => "transfer_log",
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
            [
                "zone_journal",
                "zone_versions",
                "activity_log",
                "access_log",
                "transfer_log",
            ]
        );

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_pruned_rows_total", "table"),
            expected
        );
    }
}
