//! Holding a probe's verdict to the state it was computed from, across the
//! network wait between an unlocked read and the locked write.

use crate::{
    error::ServiceError,
    model::{dnssec_key::DnssecKey, zone::Zone},
};

/// The `fingerprint` of the zone and keys a probe's verdict rests on,
/// recomputed under the lock: a different one means another state.
pub(crate) struct ProbedSnapshot<T, F> {
    fingerprint: T,
    of: F,
}

impl<T: PartialEq, F: Fn(&Zone, &[DnssecKey]) -> Result<T, ServiceError>> ProbedSnapshot<T, F> {
    pub(crate) fn take(zone: &Zone, keys: &[DnssecKey], of: F) -> Result<Self, ServiceError> {
        Ok(Self {
            fingerprint: of(zone, keys)?,
            of,
        })
    }

    /// `DNSSEC_STATE_CHANGED` unless the locked `zone` and `keys` fingerprint alike.
    pub(crate) fn require_same(&self, zone: &Zone, keys: &[DnssecKey]) -> Result<(), ServiceError> {
        if (self.of)(zone, keys)? != self.fingerprint {
            return Err(ServiceError::dnssec_state_changed(zone.name.as_str()));
        }
        Ok(())
    }
}
