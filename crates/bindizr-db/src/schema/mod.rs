//! Startup DDL, duplicated per backend for its types, indexes, and placeholders.
//!
//! RFC 1035, Section 5.1 escapes can quadruple a wire name, hence `VARCHAR(1024)`.
//!
//! Timestamps must be bound, never defaulted to the database clock; seed the
//! `default` DNSSEC policy separately so its `created_at` follows the same rule.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sqlite;
