//! Table rows for CLI output, each built from the typed daemon response so
//! the column set is all this module decides: a cell shared or assembled from
//! several fields comes from `display`, one field's label from the row's `From`.

mod dnssec;
mod history;
mod import;
mod logs;
mod record;
mod role;
mod secondary;
mod token;
mod tsig_key;
mod zone;

pub(crate) use dnssec::{DnssecKeyRow, DnssecPolicyRow};
pub(crate) use history::{RollbackSummaryRow, VersionRecordRow, VersionRow};
pub(crate) use import::{ImportSummaryRow, ImportZonesRow};
pub(crate) use logs::{AccessLogRow, AuditLogRow, TransferLogRow};
pub(crate) use record::RecordRow;
pub(crate) use role::{RoleGrantRow, RoleRow};
pub(crate) use secondary::{SecondaryRow, SecondaryStatusRow};
pub(crate) use token::TokenRow;
pub(crate) use tsig_key::TsigKeyRow;
pub(crate) use zone::ZoneRow;

#[cfg(test)]
mod tests {
    use bindizr_service::types::{CreateTokenResponse, SingleTsigKeyResponse};
    use serde_json::json;
    use tabled::Tabled;

    use super::*;

    /// Verify that the deliberate table rendering reveals what Debug redacts.
    #[test]
    fn credential_table_cells_reveal_secrets_without_debugging_them() {
        let tsig_key: SingleTsigKeyResponse = serde_json::from_value(json!({
            "tsig_key": {"id": 1, "name": "test", "algorithm": "hmac-sha256",
                "role_name": "admin", "created_at": "2026-01-01T00:00:00Z"},
            "secret": "private-fixture"
        }))
        .unwrap();
        let token: CreateTokenResponse = serde_json::from_value(json!({
            "token": {"id": 1, "name": "test", "description": null, "role_name": "admin",
                "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "last_used_at": null},
            "secret": "private-fixture"
        }))
        .unwrap();
        let tsig_row = TsigKeyRow::from(&tsig_key);
        let token_row = TokenRow::from(&token);

        for debug in [format!("{tsig_row:#?}"), format!("{token_row:?}")] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("private-fixture"));
        }
        assert!(
            tsig_row
                .fields()
                .iter()
                .any(|field| field == "private-fixture")
        );
        assert!(
            token_row
                .fields()
                .iter()
                .any(|field| field == "private-fixture")
        );
    }
}
