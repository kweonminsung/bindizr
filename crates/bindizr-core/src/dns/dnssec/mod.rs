//! DNSSEC signing: key material, the RDATA it implies, and the signed view a
//! zone's records produce. Pure computation; when to sign and what to do with
//! the result is the service's.

mod key;
mod key_file;
mod rdata;
mod signed_view;

use domain::base::{Name, iana::Rtype};
pub use key::generate_key;
pub use key_file::import_key;
pub use rdata::{DS_DIGEST_TYPES, rdata_presentation};
pub use signed_view::{SignedViewDiff, SignedViewParams};

use crate::{
    dns::name::{OwnerName, ParseNameError, ZoneName},
    model::dnssec_record::DnssecRecordType,
};

/// The name form the `domain` crate's DNSSEC machinery takes.
pub type WireName = Name<Vec<u8>>;

/// A typed name's wire bytes into the domain form.
pub(crate) fn to_wire_name(wire: Result<Vec<u8>, ParseNameError>) -> Result<WireName, String> {
    let wire = wire.map_err(|e| e.to_string())?;
    Name::from_octets(wire).map_err(|e| format!("invalid wire name: {}", e))
}

impl ZoneName {
    /// The zone apex in the domain form the DNSSEC machinery takes.
    pub fn to_wire_name(&self) -> Result<WireName, String> {
        to_wire_name(self.to_wire())
    }
}

impl OwnerName {
    /// The owner, absolute within `zone_name`, in the domain form the DNSSEC
    /// machinery takes.
    pub fn to_wire_name(&self, zone_name: &ZoneName) -> Result<WireName, String> {
        to_wire_name(self.to_wire(zone_name))
    }
}

impl TryFrom<Rtype> for DnssecRecordType {
    type Error = String;

    /// The stored DNSSEC record type a wire record type maps to.
    fn try_from(rtype: Rtype) -> Result<Self, Self::Error> {
        DnssecRecordType::try_from(rtype.to_int() as i32)
    }
}
