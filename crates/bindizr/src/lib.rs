//! The bindizr executable's internals: the CLI, HTTP API, and Unix-socket
//! control server.

mod api;
mod cli;
mod socket;

pub use cli::execute;
