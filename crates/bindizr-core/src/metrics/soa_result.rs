/// How an SOA query ended, as the SOA counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoaResult {
    Ok,
    Refused,
    NotAuth,
    Failed,
}

impl SoaResult {
    pub(crate) const ALL: [Self; 4] = [Self::Ok, Self::Refused, Self::NotAuth, Self::Failed];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::NotAuth => "notauth",
            Self::Failed => "failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics;

    /// Verify that canonical spellings remain stable in the Prometheus exposition.
    #[test]
    fn soa_result_spells_itself_once() {
        let spellings = SoaResult::ALL.map(SoaResult::as_str);
        assert_eq!(spellings, ["ok", "refused", "notauth", "failed"]);

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_soa_queries_total", "result"),
            expected
        );
    }
}
