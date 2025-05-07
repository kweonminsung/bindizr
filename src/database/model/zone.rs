use chrono::{DateTime, Utc};

// SOA 레코드의 기본 생성 및 NS 레코드의 기본 생성을 위한 구조체
#[derive(Debug, PartialEq, Eq)]
pub struct Zone {
    pub id: i32,

    pub name: String, // 존 이름 (예: "example.com")

    pub primary_ns: String, // 기본 네임서버 (예: "ns1.example.com")

    pub admin_email: String, // 관리자 이메일 (예: "admin@example.com")

    pub ttl: i32, // 기본 TTL 값 (초 단위)

    pub serial: i32, // 시리얼 번호

    pub refresh: i32, // 리프레시 주기 (초 단위)

    pub retry: i32, // 재시도 주기 (초 단위)

    pub expire: i32, // 만료 주기 (초 단위)

    pub minimum_ttl: i32, // 최소 TTL 값 (초 단위)

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}
