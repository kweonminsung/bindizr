pub(super) struct SoaRecordValue<'a> {
    value: &'a str,
}

impl<'a> SoaRecordValue<'a> {
    pub(super) fn parse(value: &'a str) -> Self {
        Self { value }
    }

    pub(super) fn canonical(&self) -> String {
        self.value.to_string()
    }
}
