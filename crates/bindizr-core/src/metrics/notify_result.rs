/// How an outbound NOTIFY ended, as the NOTIFY counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyResult {
    Ok,
    Failed,
    /// Nothing was sent, so it is kept apart from the send failures it would
    /// otherwise inflate.
    ResolveFailed,
}

impl NotifyResult {
    pub(crate) const ALL: [Self; 3] = [Self::Ok, Self::Failed, Self::ResolveFailed];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::ResolveFailed => "resolve_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics;

    /// Verify that canonical spellings remain stable in the Prometheus exposition.
    #[test]
    fn notify_result_spells_itself_once() {
        let spellings = NotifyResult::ALL.map(NotifyResult::as_str);
        assert_eq!(spellings, ["ok", "failed", "resolve_failed"]);

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_notify_sent_total", "result"),
            expected
        );
    }
}
