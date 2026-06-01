use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Record {
    pub id: i32,
    pub name: String, // domain name (e.g.: "www.example.com")
    #[sqlx(try_from = "String")]
    pub record_type: RecordType, // record type
    pub value: String, // record value (e.g.: IP address, CNAME, etc.)
    pub ttl: Option<i32>, // TTL (seconds)
    pub priority: Option<i32>, // priority (for MX and SRV records)
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
}

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordWithZone {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
    pub zone_name: String,
}

impl RecordWithZone {
    pub fn new(record: Record, zone_name: String) -> Self {
        Self {
            id: record.id,
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
            created_at: record.created_at,
            zone_id: record.zone_id,
            zone_name,
        }
    }

    pub fn record(&self) -> Record {
        Record {
            id: self.id,
            name: self.name.clone(),
            record_type: self.record_type.clone(),
            value: self.value.clone(),
            ttl: self.ttl,
            priority: self.priority,
            created_at: self.created_at,
            zone_id: self.zone_id,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
}
impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for RecordType {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "NS" => Ok(RecordType::NS),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "PTR" => Ok(RecordType::PTR),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

impl RecordType {
    pub fn as_str(&self) -> &str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::PTR => "PTR",
        }
    }

    pub fn is_name_like_value(&self) -> bool {
        matches!(
            self,
            RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::MX | RecordType::SRV
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Record, RecordType, RecordWithZone};
    use chrono::Utc;

    fn sample_record() -> Record {
        Record {
            id: 42,
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.1".to_string(),
            ttl: Some(300),
            priority: None,
            created_at: Utc::now(),
            zone_id: 7,
        }
    }

    // --- RecordWithZone::new ---

    #[test]
    fn record_with_zone_new_copies_all_record_fields() {
        let record = sample_record();
        let zone_name = "example.com".to_string();
        let record_with_zone = RecordWithZone::new(record.clone(), zone_name.clone());

        assert_eq!(record_with_zone.id, record.id);
        assert_eq!(record_with_zone.name, record.name);
        assert_eq!(record_with_zone.record_type, record.record_type);
        assert_eq!(record_with_zone.value, record.value);
        assert_eq!(record_with_zone.ttl, record.ttl);
        assert_eq!(record_with_zone.priority, record.priority);
        assert_eq!(record_with_zone.created_at, record.created_at);
        assert_eq!(record_with_zone.zone_id, record.zone_id);
        assert_eq!(record_with_zone.zone_name, zone_name);
    }

    #[test]
    fn record_with_zone_new_preserves_optional_priority_when_present() {
        let mut record = sample_record();
        record.record_type = RecordType::MX;
        record.priority = Some(10);

        let rz = RecordWithZone::new(record.clone(), "example.com".to_string());
        assert_eq!(rz.priority, Some(10));
    }

    // --- RecordWithZone::record ---

    #[test]
    fn record_with_zone_record_returns_equivalent_record() {
        let original = sample_record();
        let rz = RecordWithZone::new(original.clone(), "example.com".to_string());
        let roundtrip = rz.record();

        assert_eq!(roundtrip.id, original.id);
        assert_eq!(roundtrip.name, original.name);
        assert_eq!(roundtrip.record_type, original.record_type);
        assert_eq!(roundtrip.value, original.value);
        assert_eq!(roundtrip.ttl, original.ttl);
        assert_eq!(roundtrip.priority, original.priority);
        assert_eq!(roundtrip.created_at, original.created_at);
        assert_eq!(roundtrip.zone_id, original.zone_id);
    }

    #[test]
    fn record_with_zone_record_does_not_include_zone_name() {
        // Record struct has no zone_name field; this just verifies compilation
        // and that zone_name is not leaked into Record.
        let rz = RecordWithZone::new(sample_record(), "example.com".to_string());
        let record = rz.record();
        // Record has no zone_name field - confirmed by field access
        let _ = record.id; // access a field to ensure Record is used
    }

    // --- RecordType::is_name_like_value ---

    #[test]
    fn is_name_like_value_returns_true_for_name_types() {
        assert!(RecordType::CNAME.is_name_like_value());
        assert!(RecordType::NS.is_name_like_value());
        assert!(RecordType::PTR.is_name_like_value());
        assert!(RecordType::MX.is_name_like_value());
        assert!(RecordType::SRV.is_name_like_value());
    }

    #[test]
    fn is_name_like_value_returns_false_for_non_name_types() {
        assert!(!RecordType::A.is_name_like_value());
        assert!(!RecordType::AAAA.is_name_like_value());
        assert!(!RecordType::TXT.is_name_like_value());
        assert!(!RecordType::SOA.is_name_like_value());
    }
}
