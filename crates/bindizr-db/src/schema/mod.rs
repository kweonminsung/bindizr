//! Table-creation DDL, one module per backend, run at startup to bring the
//! schema up. The three are duplicated on purpose: each spells its own column
//! types, index syntax, and placeholder form.
//!
//! Name columns hold the RFC 1035, Section 5.1 rendering, whose `\046` escape
//! can quadruple a name inside the 255-octet wire limit, hence `VARCHAR(1024)`.
//!
//! No timestamp column carries a `DEFAULT CURRENT_TIMESTAMP`: an insert that
//! forgets to bind one must fail rather than take the database server's clock.
//!
//! The `default` DNSSEC policy is seeded separately from the table statements
//! so its `created_at` can be bound like every other timestamp.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sqlite;
