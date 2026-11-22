use domain::base::iana::OptRcode;

/// How an UPDATE request ended, as the nsupdate counter labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsupdateResult {
    /// A TSIG failure answers with its own NOTAUTH, so it is kept apart from
    /// the NOTAUTH an update refused on its merits gets.
    TsigFailed,
    /// Every other outcome is named by the response code, extended ones such
    /// as BADVERS included: a bounded set, never the free-form message.
    Rcode(OptRcode),
}

impl NsupdateResult {
    pub(crate) const ALL: [Self; 12] = [
        Self::TsigFailed,
        Self::Rcode(OptRcode::NOERROR),
        Self::Rcode(OptRcode::FORMERR),
        Self::Rcode(OptRcode::REFUSED),
        Self::Rcode(OptRcode::YXDOMAIN),
        Self::Rcode(OptRcode::YXRRSET),
        Self::Rcode(OptRcode::NXDOMAIN),
        Self::Rcode(OptRcode::NXRRSET),
        Self::Rcode(OptRcode::NOTAUTH),
        Self::Rcode(OptRcode::NOTZONE),
        Self::Rcode(OptRcode::SERVFAIL),
        Self::Rcode(OptRcode::BADVERS),
    ];

    /// Return the metric label value of this nsupdate result.
    pub(crate) fn metric_label(self) -> &'static str {
        let Self::Rcode(rcode) = self else {
            return "tsig_failed";
        };

        match rcode {
            OptRcode::NOERROR => "noerror",
            OptRcode::FORMERR => "formerr",
            OptRcode::REFUSED => "refused",
            OptRcode::YXDOMAIN => "yxdomain",
            OptRcode::YXRRSET => "yxrrset",
            OptRcode::NXDOMAIN => "nxdomain",
            OptRcode::NXRRSET => "nxrrset",
            OptRcode::NOTAUTH => "notauth",
            OptRcode::NOTZONE => "notzone",
            OptRcode::SERVFAIL => "servfail",
            OptRcode::BADVERS => "badvers",
            _ => "other",
        }
    }
}
