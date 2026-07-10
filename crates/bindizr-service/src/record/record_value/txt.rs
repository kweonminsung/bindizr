use std::borrow::Cow;

pub(super) struct TxtRecordValue<'a> {
    value: &'a str,
}

impl<'a> TxtRecordValue<'a> {
    pub(super) fn parse(value: &'a str) -> Self {
        Self { value }
    }

    /// TXT values are already stored in canonical form, so borrow rather than copy.
    pub(super) fn canonical(&self) -> Cow<'a, str> {
        Cow::Borrowed(self.value)
    }
}
