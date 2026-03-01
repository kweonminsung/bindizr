pub mod axfr;
pub mod delta;
pub mod error;
pub mod ixfr;
pub mod server;
pub mod wire;

pub use error::XfrError;
pub use server::XfrServer;

use crate::log_info;

pub fn initialize() {
    log_info!("XFR module initialized");
}
