//! Change origin shared by caller identity, audit logs, and zone history.

use crate::model::change::{ChangeActor, ChangeSource};

/// The origin of a managed change and the named credential behind it, independent of permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangeOrigin {
    pub(crate) source: ChangeSource,
    pub(crate) actor: Option<ChangeActor>,
}

impl ChangeOrigin {
    /// The scheduler, acting on nobody's request.
    pub(crate) fn system() -> Self {
        ChangeOrigin {
            source: ChangeSource::System,
            actor: None,
        }
    }
}
