//! Backend-specific startup DDL; escaped names need VARCHAR(1024) (RFC 1035, Section 5.1).
//! Bind timestamps instead of using the DB clock, including the separately seeded `default` policy.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sqlite;
