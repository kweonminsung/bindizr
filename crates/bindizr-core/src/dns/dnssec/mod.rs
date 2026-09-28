//! DNSSEC signing: key material, the RDATA it implies, and the signed view a
//! zone's records produce. Pure computation; when to sign and what to do with
//! the result is the service's.

mod key;
mod key_file;
mod rdata;
mod signed_view;

use domain::base::{Name, iana::Rtype};
pub use key::{GenerateKeyError, generate_key};
pub use key_file::{ImportKeyError, import_key};
pub use rdata::{DS_DIGEST_TYPES, KeyRdataError};
pub use signed_view::{SignZoneError, SignedViewDiff, SignedViewParams};
use thiserror::Error;

use crate::{
    dns::{
        LibraryError,
        name::{OwnerName, ParseNameError, ZoneName},
    },
    model::dnssec_record::{DnssecRecordType, ParseDnssecRecordTypeError},
};

/// A typed name whose wire bytes the `domain` crate did not accept.
#[derive(Debug, Error)]
pub enum WireNameError {
    #[error(transparent)]
    Name(#[from] ParseNameError),
    #[error("invalid wire name: {0}")]
    Octets(#[source] LibraryError),
}

/// The name form the `domain` crate's DNSSEC machinery takes.
pub type WireName = Name<Vec<u8>>;

/// A typed name's wire bytes into the domain form.
pub(crate) fn to_wire_name(
    wire: Result<Vec<u8>, ParseNameError>,
) -> Result<WireName, WireNameError> {
    Name::from_octets(wire?).map_err(|e| WireNameError::Octets(Box::new(e)))
}

impl ZoneName {
    /// The zone apex in the domain form the DNSSEC machinery takes.
    pub fn to_wire_name(&self) -> Result<WireName, WireNameError> {
        to_wire_name(self.to_wire())
    }
}

impl OwnerName {
    /// The owner, absolute within `zone_name`, in the domain form the DNSSEC
    /// machinery takes.
    pub fn to_wire_name(&self, zone_name: &ZoneName) -> Result<WireName, WireNameError> {
        to_wire_name(self.to_wire(zone_name))
    }
}

impl TryFrom<Rtype> for DnssecRecordType {
    type Error = ParseDnssecRecordTypeError;

    /// The stored DNSSEC record type a wire record type maps to.
    fn try_from(rtype: Rtype) -> Result<Self, Self::Error> {
        DnssecRecordType::try_from(rtype.to_int() as i32)
    }
}
