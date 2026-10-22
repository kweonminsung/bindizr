//! CLI, daemon runtime and HTTP, DNS and Unix-socket front ends.

mod api;
mod cli;
mod daemon;
mod dns;
mod params;
mod shutdown;
mod socket;
mod tls;

pub use cli::execute;
