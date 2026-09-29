//! The database models every layer above shares.

/// An entity's row id as its own type, so a zone's id cannot stand in for a
/// record's. Every insert starts from `UNWRITTEN`, the `0` placeholder the
/// database replaces with the id it assigns.
macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
            sqlx::Type,
        )]
        #[serde(transparent)]
        #[sqlx(transparent)]
        pub struct $name(i32);

        impl $name {
            /// The placeholder of a row not yet written; the database assigns
            /// the id on insert.
            pub const UNWRITTEN: Self = Self(0);

            /// The id the database gave the row, or `None` for the placeholder.
            pub fn written(self) -> Option<Self> {
                (self != Self::UNWRITTEN).then_some(self)
            }
        }

        impl From<i32> for $name {
            /// Wrap a row id as the database numbered it.
            fn from(id: i32) -> Self {
                Self(id)
            }
        }

        impl From<$name> for i32 {
            /// The row form.
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            /// Write the id in decimal.
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

pub mod api_token;
pub mod dnssec_key;
pub mod dnssec_policy;
pub mod dnssec_record;
pub mod grant_pattern;
pub mod record;
pub mod secondary;
pub mod token_grant;
pub mod transfer;
pub mod tsig_grant;
pub mod tsig_key;
pub mod zone;
pub mod zone_change;
pub mod zone_version;
