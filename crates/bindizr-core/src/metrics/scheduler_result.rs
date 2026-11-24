/// How a scheduler pass ended, as the scheduler counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerResult {
    Ok,
    Failed,
    /// The pass unwound; the scheduler itself survived.
    Panicked,
}

impl SchedulerResult {
    pub(crate) const ALL: [Self; 3] = [Self::Ok, Self::Failed, Self::Panicked];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Panicked => "panic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics;

    /// Verify that canonical spellings remain stable in the Prometheus exposition.
    #[test]
    fn scheduler_result_spells_itself_once() {
        let spellings = SchedulerResult::ALL.map(SchedulerResult::as_str);
        assert_eq!(spellings, ["ok", "failed", "panic"]);

        let mut expected = spellings.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(
            metrics::tests::metric_labels("bindizr_dnssec_scheduler_runs_total", "result"),
            expected
        );
    }
}
