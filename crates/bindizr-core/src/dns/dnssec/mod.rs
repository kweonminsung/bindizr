//! DNSSEC signing: key material, the RDATA it implies, and the signed view a
//! zone's records produce. Pure computation; when to sign and what to do with
//! the result is the service's.

mod key;
mod key_file;
mod rdata;
mod signed_view;

use domain::base::Name;
pub use key::generate_key;
pub use key_file::{import_key, to_bind_private_file};
pub use rdata::{DS_DIGEST_TYPES, ds_rdata_for, rdata_presentation};
pub use signed_view::{SignedViewDiff, SignedViewParams};

use crate::dns::name::ParseNameError;

/// The name form the `domain` crate's DNSSEC machinery takes.
pub type WireName = Name<Vec<u8>>;

/// A typed name's wire bytes into the domain form.
pub fn to_wire_name(wire: Result<Vec<u8>, ParseNameError>) -> Result<WireName, String> {
    let wire = wire.map_err(|e| e.to_string())?;
    Name::from_octets(wire).map_err(|e| format!("invalid wire name: {}", e))
}
