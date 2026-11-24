use bindizr_core::dns::dnssec::KeyTag;
use bindizr_core::model::dnssec_key::DnssecKeyId;
use bindizr_core::model::dnssec_policy::PolicyId;
use bindizr_service::types::{DnssecKeyResponse, DnssecPolicyResponse};
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct DnssecKeyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: DnssecKeyId,
    #[tabled(rename = "ROLE")]
    pub(crate) role: String,
    #[tabled(rename = "STATE")]
    pub(crate) state: String,
    #[tabled(rename = "STATE-CHANGED-AT")]
    pub(crate) state_changed_at: String,
    #[tabled(rename = "ELIGIBLE-AT")]
    pub(crate) eligible_at: String,
    #[tabled(rename = "ALGORITHM")]
    pub(crate) algorithm: String,
    #[tabled(rename = "KEY-TAG")]
    pub(crate) key_tag: KeyTag,
    #[tabled(rename = "DNSKEY")]
    pub(crate) dnskey: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&DnssecKeyResponse> for DnssecKeyRow {
    /// Build a CLI table row from the DNSSEC key info.
    fn from(key: &DnssecKeyResponse) -> Self {
        Self {
            id: key.id,
            role: key.role.to_string(),
            state: key.state.to_string(),
            state_changed_at: display::display_time(key.state_changed_at),
            eligible_at: display::display_option_time(&key.eligible_at),
            algorithm: key.algorithm.to_string(),
            key_tag: key.key_tag,
            dnskey: key.dnskey.clone(),
            created_at: display::display_time(key.created_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct DnssecPolicyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: PolicyId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "ALGORITHM")]
    pub(crate) algorithm: String,
    #[tabled(rename = "DENIAL")]
    pub(crate) denial: String,
    #[tabled(rename = "KEY-LAYOUT")]
    pub(crate) key_layout: String,
    #[tabled(rename = "VALIDITY")]
    pub(crate) validity: String,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: String,
    #[tabled(rename = "ZSK-LIFETIME")]
    pub(crate) zsk_lifetime: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&DnssecPolicyResponse> for DnssecPolicyRow {
    /// Build a CLI table row from the DNSSEC policy response.
    fn from(policy: &DnssecPolicyResponse) -> Self {
        Self {
            id: policy.id,
            name: policy.name.clone(),
            algorithm: policy.algorithm.to_string(),
            denial: policy.denial.to_string(),
            key_layout: policy.key_layout.to_string(),
            validity: format!("{}d", policy.signature_validity_days),
            refresh: format!("{}d", policy.signature_refresh_days),
            zsk_lifetime: if policy.zsk_lifetime_days.as_days() == 0 {
                display::MISSING_CELL.to_string()
            } else {
                format!("{}d", policy.zsk_lifetime_days)
            },
            created_at: display::display_time(policy.created_at),
        }
    }
}
