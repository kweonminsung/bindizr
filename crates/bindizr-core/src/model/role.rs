use chrono::{DateTime, Utc};
use sqlx::FromRow;

id_newtype!(
    /// The id of a role row.
    RoleId
);

/// A named set of rights that API tokens and TSIG keys authenticate into; the
/// rights are its [`super::role_grant::RoleGrant`] rows.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Role {
    pub id: RoleId,
    /// Unique human-facing identifier; credentials and the CLI reference a role by name.
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Role {
    /// The built-in role holding every action in every zone, ensured at
    /// startup so the first token has something to authenticate into.
    pub const ADMIN: &str = "admin";

    /// Whether this is the built-in role, which can be neither changed nor deleted.
    pub fn is_builtin(&self) -> bool {
        self.name == Self::ADMIN
    }
}
