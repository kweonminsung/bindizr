use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub id: i32,

    pub name: String, // 도메인 이름 (예: "example.com")

    pub record_type: RecordType, // 레코드 유형

    pub value: String, // 레코드 값 (예: IP 주소, 도메인 이름 등)

    pub ttl: i32, // TTL 값 (초 단위)

    pub priority: Option<i32>, // 우선순위 (MX 레코드 등에서 사용, 다른 레코드에서는 None)

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,

    pub zone_id: i32,
}

#[derive(Debug, PartialEq, Eq)]
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
