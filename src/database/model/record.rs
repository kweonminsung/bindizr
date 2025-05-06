#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub id: i32, // 고유 ID (기본 키)

    pub name: String, // 도메인 이름 (예: "example.com")

    pub record_type: RecordType, // 레코드 유형 (enum으로 변경)

    pub value: String, // 레코드 값 (예: IP 주소, 도메인 이름 등)

    pub ttl: i32, // TTL(Time To Live) 값 (초 단위)

    pub priority: Option<i32>, // 우선순위 (MX 레코드 등에서 사용, 다른 레코드에서는 None)

    pub created_at: DateTimeUtc,

    pub updated_at: DateTimeUtc,
}

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
    OTHER, // 기타 레코드 유형
}
