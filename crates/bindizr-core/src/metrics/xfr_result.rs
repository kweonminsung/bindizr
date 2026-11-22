/// How a zone transfer request ended, as the transfer counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrResult {
    Ok,
    Refused,
    NotAuth,
    /// Answered over UDP with TC set, or an IXFR with the zone's SOA alone;
    /// the transfer follows over TCP.
    Truncated,
    Failed,
}

impl XfrResult {
    pub(crate) const ALL: [Self; 5] = [
        Self::Ok,
        Self::Refused,
        Self::NotAuth,
        Self::Truncated,
        Self::Failed,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::NotAuth => "notauth",
            Self::Truncated => "truncated",
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
    fn xfr_result_spells_itself_once() {
        let spellings = XfrResult::ALL.map(XfrResult::as_str);
        assert_eq!(
            spellings,
            ["ok", "refused", "notauth", "truncated", "failed"]
        );

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_xfr_total", "result"),
            expected
        );
    }
}
