//! The bindizr executable's internals: the CLI, the daemon runtime, the HTTP
//! API, and the Unix-socket control server.

mod api;
mod cli;
mod daemon;
mod net;
mod socket;

pub use cli::execute;
