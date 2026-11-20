//! Compute DNSSEC keys, RDATA and signed zone views; the service owns scheduling and storage.

mod key;
mod key_file;
mod key_tag;
mod rdata;
mod signed_view;

use domain::base::Record;
pub use key::GenerateKeyError;
pub use key_file::ImportKeyError;
pub use key_tag::{ConvertKeyTagError, KeyTag};
pub use rdata::{DS_DIGEST_TYPE, DS_DIGEST_TYPES, EncodeKeyRdataError};
pub use signed_view::{SignZoneError, SignedViewDiff, SignedViewParams, SigningPass};

use crate::dns::name::WireName;

/// A record in the `domain` crate's form, owned by a [`WireName`].
pub(crate) type WireRecord<D> = Record<WireName, D>;
