/// Whether a zone-cache lookup found its entry, as the lookup counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZoneCacheLookup {
    Hit,
    Miss,
}

impl ZoneCacheLookup {
    pub(crate) const ALL: [Self; 2] = [Self::Hit, Self::Miss];

    /// Return the canonical text representation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics;

    /// Verify that canonical spellings remain stable in the Prometheus exposition.
    #[test]
    fn zone_cache_lookup_spells_itself_once() {
        let spellings = ZoneCacheLookup::ALL.map(ZoneCacheLookup::as_str);
        assert_eq!(spellings, ["hit", "miss"]);

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_zone_cache_lookups_total", "result"),
            expected
        );
    }
}
