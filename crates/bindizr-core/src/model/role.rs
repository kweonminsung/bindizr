use chrono::{DateTime, Utc};
use sqlx::FromRow;

id_newtype!(
    /// The id of a role row.
    RoleId
);

/// A named set of rights that API tokens and TSIG keys authenticate into; the
/// rights are its [`crate::model::role_grant::RoleGrant`] rows.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Role {
    pub id: RoleId,
    /// Unique human-facing identifier; credentials and the CLI reference a role by name.
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Role {
    /// The built-in role holding every action in all zones, ensured at
    /// startup so the first token has something to authenticate into.
    pub const ADMIN: &str = "admin";

    /// Return whether this is the built-in role, which can be neither changed nor deleted.
    pub fn is_builtin(&self) -> bool {
        self.name == Self::ADMIN
    }
}

/// A role joined with its credential and grant cardinalities.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct RoleWithCounts {
    #[sqlx(flatten)]
    pub role: Role,
    #[sqlx(try_from = "i64")]
    pub grant_count: u64,
    #[sqlx(try_from = "i64")]
    pub token_count: u64,
    #[sqlx(try_from = "i64")]
    pub tsig_key_count: u64,
}
