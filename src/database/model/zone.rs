use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq, Eq)]
pub struct Zone {
    pub id: i32, // 고유 ID (기본 키)

    pub name: String, // 존 이름 (예: "example.com")

    pub admin_email: String, // 관리자 이메일 (예: "admin@example.com")

    pub ttl: i32, // 기본 TTL 값 (초 단위)

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}
