//! The bindizr executable's internals: the CLI, HTTP API, and Unix-socket
//! control server.

mod api;
mod cli;
mod net;
mod socket;

pub use cli::execute;
