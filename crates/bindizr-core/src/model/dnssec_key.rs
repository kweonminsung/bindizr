use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Supported DNSSEC signing algorithms, with their IANA numbers and mnemonics.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecAlgorithm {
    /// RSA with SHA-256, algorithm 8 (RFC 5702).
    RsaSha256,
    /// RSA with SHA-512, algorithm 10 (RFC 5702).
    RsaSha512,
    /// ECDSA Curve P-256 with SHA-256, algorithm 13 (RFC 6605).
    EcdsaP256Sha256,
    /// ECDSA Curve P-384 with SHA-384, algorithm 14 (RFC 6605).
    EcdsaP384Sha384,
    /// Ed25519, algorithm 15 (RFC 8080).
    Ed25519,
    /// Ed448, algorithm 16 (RFC 8080).
    Ed448,
}

impl DnssecAlgorithm {
    /// IANA algorithm number, the storage form.
    pub fn to_int(self) -> i32 {
        match self {
            DnssecAlgorithm::RsaSha256 => 8,
            DnssecAlgorithm::RsaSha512 => 10,
            DnssecAlgorithm::EcdsaP256Sha256 => 13,
            DnssecAlgorithm::EcdsaP384Sha384 => 14,
            DnssecAlgorithm::Ed25519 => 15,
            DnssecAlgorithm::Ed448 => 16,
        }
    }

    /// Parse a supported DNSSEC algorithm number.
    pub fn from_int(value: i32) -> Option<Self> {
        match value {
            8 => Some(DnssecAlgorithm::RsaSha256),
            10 => Some(DnssecAlgorithm::RsaSha512),
            13 => Some(DnssecAlgorithm::EcdsaP256Sha256),
            14 => Some(DnssecAlgorithm::EcdsaP384Sha384),
            15 => Some(DnssecAlgorithm::Ed25519),
            16 => Some(DnssecAlgorithm::Ed448),
            _ => None,
        }
    }

    /// IANA mnemonic in lowercase, the presentation/input form.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecAlgorithm::RsaSha256 => "rsasha256",
            DnssecAlgorithm::RsaSha512 => "rsasha512",
            DnssecAlgorithm::EcdsaP256Sha256 => "ecdsap256sha256",
            DnssecAlgorithm::EcdsaP384Sha384 => "ecdsap384sha384",
            DnssecAlgorithm::Ed25519 => "ed25519",
            DnssecAlgorithm::Ed448 => "ed448",
        }
    }

    /// DS digest type the algorithm's DS pairs with: 4 = SHA-384 for P-384
    /// (RFC 6605, Section 4), otherwise 2 = SHA-256 (RFC 4509).
    pub fn ds_digest_type(self) -> u8 {
        match self {
            DnssecAlgorithm::EcdsaP384Sha384 => 4,
            _ => 2,
        }
    }

    /// All supported algorithm names, for error messages.
    fn supported_names() -> &'static [&'static str] {
        &[
            "rsasha256",
            "rsasha512",
            "ecdsap256sha256",
            "ecdsap384sha384",
            "ed25519",
            "ed448",
        ]
    }
}

impl std::fmt::Display for DnssecAlgorithm {
    /// Write the DNSSEC algorithm in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecAlgorithm {
    type Err = String;

    /// Parse a DNSSEC algorithm from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "rsasha256" => Ok(DnssecAlgorithm::RsaSha256),
            "rsasha512" => Ok(DnssecAlgorithm::RsaSha512),
            "ecdsap256sha256" => Ok(DnssecAlgorithm::EcdsaP256Sha256),
            "ecdsap384sha384" => Ok(DnssecAlgorithm::EcdsaP384Sha384),
            "ed25519" => Ok(DnssecAlgorithm::Ed25519),
            "ed448" => Ok(DnssecAlgorithm::Ed448),
            _ => Err(format!(
                "unsupported DNSSEC algorithm '{}' (supported: {})",
                s,
                DnssecAlgorithm::supported_names().join(", ")
            )),
        }
    }
}

impl TryFrom<i32> for DnssecAlgorithm {
    type Error = String;

    /// Validate and convert the stored value into a DNSSEC algorithm.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        DnssecAlgorithm::from_int(value)
            .ok_or_else(|| format!("unsupported DNSSEC algorithm number {}", value))
    }
}

/// What a key signs: a CSK everything, a KSK/ZSK pair splits the apex key
/// RRsets (whose signer the parent DS must name, RFC 7344, Section 4.1)
/// from the zone data.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecKeyRole {
    Csk,
    Ksk,
    Zsk,
}

impl DnssecKeyRole {
    /// Return the text representation of this DNSSEC key role.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecKeyRole::Csk => "csk",
            DnssecKeyRole::Ksk => "ksk",
            DnssecKeyRole::Zsk => "zsk",
        }
    }

    /// Whether the key is represented in the parent DS set (SEP keys).
    pub fn is_sep(&self) -> bool {
        matches!(self, DnssecKeyRole::Csk | DnssecKeyRole::Ksk)
    }

    /// DNSKEY flags field: ZONE, plus SEP for keys the parent DS names
    /// (RFC 4034, Section 2.1.1).
    pub fn flags(&self) -> u16 {
        if self.is_sep() { 257 } else { 256 }
    }
}

impl std::fmt::Display for DnssecKeyRole {
    /// Write the DNSSEC key role in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecKeyRole {
    type Err = String;

    /// Parse a DNSSEC key role from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "csk" => Ok(DnssecKeyRole::Csk),
            "ksk" => Ok(DnssecKeyRole::Ksk),
            "zsk" => Ok(DnssecKeyRole::Zsk),
            _ => Err(format!(
                "unsupported DNSSEC key role '{}' (supported: csk, ksk, zsk)",
                s
            )),
        }
    }
}

impl TryFrom<String> for DnssecKeyRole {
    type Error = String;

    /// Validate and convert the stored value into a DNSSEC key role.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// Rollover lifecycle position (RFC 7583); a settled zone holds only
/// `Active` keys.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecKeyState {
    /// Published ahead of promotion so caches learn it; an algorithm rollover
    /// may already require it to sign (see [`DnssecKey::signs_zone_data`]).
    Published,
    /// Signing normally.
    Active,
    /// Retained while cached signatures and parent DS records drain; an
    /// algorithm rollover may still require it to sign zone data.
    Retired,
}

impl DnssecKeyState {
    /// Return the text representation of this DNSSEC key state.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecKeyState::Published => "published",
            DnssecKeyState::Active => "active",
            DnssecKeyState::Retired => "retired",
        }
    }
}

impl std::fmt::Display for DnssecKeyState {
    /// Write the DNSSEC key state in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecKeyState {
    type Err = String;

    /// Parse a DNSSEC key state from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "published" => Ok(DnssecKeyState::Published),
            "active" => Ok(DnssecKeyState::Active),
            "retired" => Ok(DnssecKeyState::Retired),
            _ => Err(format!(
                "unsupported DNSSEC key state '{}' (supported: published, active, retired)",
                s
            )),
        }
    }
}

impl TryFrom<String> for DnssecKeyState {
    type Error = String;

    /// Validate and convert the stored value into a DNSSEC key state.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A zone's DNSSEC signing key; key rows mark a signed zone. Private material
/// is exported only through the daemon socket, never the HTTP API.
#[derive(Debug, Clone, FromRow)]
pub struct DnssecKey {
    pub id: i32,
    pub zone_id: i32,
    #[sqlx(try_from = "String")]
    pub role: DnssecKeyRole,
    #[sqlx(try_from = "i32")]
    pub algorithm: DnssecAlgorithm,
    /// RFC 4034, Appendix B key tag, precomputed for display and DS output.
    pub key_tag: i32,
    /// DNSKEY public-key field, base64.
    pub public_key: String,
    /// BIND private-key file format.
    pub private_key: String,
    #[sqlx(try_from = "String")]
    pub state: DnssecKeyState,
    /// When the key entered `state`.
    pub state_changed_at: DateTime<Utc>,
    /// When the key's next state transition is allowed, stamped at the
    /// transition that started the wait — a later TTL change
    /// cannot shorten it.
    pub eligible_at: DateTime<Utc>,
    /// Largest TTL among the RRsets this key has signed, so retirement knows
    /// how long resolvers can keep validating with it.
    pub max_signed_ttl: i32,
    pub created_at: DateTime<Utc>,
}

impl DnssecKey {
    /// CSK/ZSK keys sign when active, or when their algorithm has no active
    /// data signer in `keys` (RFC 6840, Section 5.11). KSKs never sign zone data.
    pub fn signs_zone_data(&self, keys: &[DnssecKey]) -> bool {
        if !matches!(self.role, DnssecKeyRole::Csk | DnssecKeyRole::Zsk) {
            return false;
        }
        if self.state == DnssecKeyState::Active {
            return true;
        }
        !keys.iter().any(|key| {
            key.id != self.id
                && matches!(key.role, DnssecKeyRole::Csk | DnssecKeyRole::Zsk)
                && key.state == DnssecKeyState::Active
                && key.algorithm == self.algorithm
        })
    }

    /// Whether the key co-signs the apex key RRsets. Every SEP key does, in
    /// every state: a validator may arrive via whichever parent DS names it.
    pub fn signs_key_record_sets(&self) -> bool {
        self.role.is_sep()
    }

    /// Whether the key waits for its DS at the parent before promotion:
    /// pre-published SEP keys (ZSKs promote without parent interaction).
    pub fn awaits_parent_ds(&self) -> bool {
        self.role.is_sep() && self.state == DnssecKeyState::Published
    }

    /// Whether the key belongs in the CDS/CDNSKEY set; excluding retired keys
    /// tells the parent to drop their DS (RFC 7344).
    pub fn wants_parent_ds(&self) -> bool {
        self.role.is_sep() && self.state != DnssecKeyState::Retired
    }

    /// The wait before a retired key may be removed: the retire interval of
    /// RFC 7583, Section 3.3.4. The key outlives the signatures it made,
    /// cached for their RRset's TTL, and — for a key a DS names — the parent's
    /// DS RRset, cached for the TTL the confirming probe saw.
    pub fn retirement_interval_secs(&self, parent_ds_ttl: Option<u32>) -> i64 {
        let signatures = i64::from(self.max_signed_ttl);
        if !self.role.is_sep() {
            return signatures;
        }
        signatures.max(i64::from(parent_ds_ttl.unwrap_or(0)))
    }
}
