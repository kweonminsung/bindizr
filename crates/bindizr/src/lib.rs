//! The bindizr executable's internals: the CLI, the daemon runtime, and the
//! front ends it serves — HTTP API, DNS server, and the Unix-socket control
//! channel.

mod api;
mod cli;
mod daemon;
mod dns;
mod net;
mod socket;

pub use cli::execute;
