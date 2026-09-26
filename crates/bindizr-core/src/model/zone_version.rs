use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Point-in-time version of a zone's SOA fields at a given serial.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ZoneVersion {
    pub id: i32,
    pub zone_id: i32,
    pub serial: i32,
    pub mname: String,
    /// Stored in SOA mailbox encoded form, unlike `Zone.rname` which holds the
    /// admin email.
    pub rname: String,
    pub default_ttl: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    /// Which plane asked for this version.
    #[sqlx(try_from = "String")]
    pub change_source: ChangeSource,
    /// The API token or TSIG key the change was made under, absent where no
    /// credential stood behind it. Copied rather than referenced, so the
    /// answer outlives the credential.
    pub changed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// The plane a zone version's change came through.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSource {
    /// An API token, global or scoped.
    Token,
    /// An RFC 2136 update, named by the TSIG key that signed it.
    Nsupdate,
    /// The DNSSEC scheduler, on nobody's request.
    System,
    /// No credential stood behind it: the daemon socket, or any request made
    /// while authentication is disabled.
    Local,
}

impl ChangeSource {
    /// Return the text representation of this change source.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeSource::Token => "token",
            ChangeSource::Nsupdate => "nsupdate",
            ChangeSource::System => "system",
            ChangeSource::Local => "local",
        }
    }
}

impl std::fmt::Display for ChangeSource {
    /// Write the change source in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ChangeSource {
    type Err = String;

    /// Parse the stored text of a change source.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "token" => Ok(ChangeSource::Token),
            "nsupdate" => Ok(ChangeSource::Nsupdate),
            "system" => Ok(ChangeSource::System),
            "local" => Ok(ChangeSource::Local),
            other => Err(format!("unknown change source '{}'", other)),
        }
    }
}

impl TryFrom<String> for ChangeSource {
    type Error = String;

    /// Validate and convert the stored value into a change source.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
