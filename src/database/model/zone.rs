use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "zone")]
pub struct Zone {
    #[sea_orm(primary_key)]
    pub id: i32, // 고유 ID (기본 키)

    pub name: String, // 존 이름 (예: "example.com")

    pub admin_email: String, // 관리자 이메일 (예: "admin@example.com")

    pub ttl: i32, // 기본 TTL 값 (초 단위)

    pub created_at: DateTimeUtc, // 생성 시간

    pub updated_at: DateTimeUtc, // 수정 시간
}
