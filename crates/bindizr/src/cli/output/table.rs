//! Table rows for CLI output, each built from the typed daemon response so
//! the column set is all this module decides; the cells come from `display`.

use bindizr_core::{
    dns::{Serial, Ttl},
    model::{
        api_token::TokenId, dnssec_key::DnssecKeyId, dnssec_policy::PolicyId, record::RecordId,
        secondary::SecondaryId, token_grant::TokenGrantId, tsig_grant::TsigGrantId,
        tsig_key::TsigKeyId, zone::ZoneId,
    },
};
use bindizr_service::types::{
    CreatedTokenResponse, DnssecKeyInfo, GetDnssecPolicyResponse, GetRecordResponse,
    GetSecondaryResponse, GetTokenGrantResponse, GetTokenResponse, GetTsigGrantResponse,
    GetTsigKeyResponse, GetZoneResponse, ImportZoneResponse, RollbackZoneResponse,
    SecondaryStatusResponse, TransferResponse, TsigKeyResponse, VersionRecordResponse,
    ZoneStatusResponse, ZoneVersionResponse,
};
use tabled::Tabled;

use super::display::{
    MISSING_CELL, display_option, display_option_time, display_record_value, display_time,
    display_transfer, display_transfer_kind, display_yes_no,
};

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ZoneRow {
    #[tabled(rename = "ID", display = "display_option")]
    pub(crate) id: Option<ZoneId>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i32,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: Serial,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: i32,
    #[tabled(rename = "RETRY")]
    pub(crate) retry: i32,
    #[tabled(rename = "EXPIRE")]
    pub(crate) expire: i32,
    #[tabled(rename = "MINIMUM-TTL")]
    pub(crate) minimum_ttl: i32,
    #[tabled(rename = "SERVED")]
    pub(crate) served: String,
    #[tabled(rename = "DESCRIPTION")]
    pub(crate) description: String,
}

impl From<&GetZoneResponse> for ZoneRow {
    /// Build a CLI table row from the zone response.
    fn from(zone: &GetZoneResponse) -> Self {
        ZoneRow {
            id: zone.id,
            name: zone.name.clone(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: i32::from(zone.default_ttl),
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: i32::from(zone.minimum_ttl),
            served: display_yes_no(&zone.enabled),
            description: display_option(&zone.description),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct RecordRow {
    #[tabled(rename = "ID", display = "display_option")]
    pub(crate) id: Option<RecordId>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: Ttl,
    #[tabled(rename = "PRIORITY", display = "display_option")]
    pub(crate) priority: Option<i32>,
    #[tabled(rename = "ZONE-ID")]
    pub(crate) zone_id: ZoneId,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
}

impl From<&GetRecordResponse> for RecordRow {
    /// Build a listing row, with the value shortened so one long record does
    /// not widen the column.
    fn from(record: &GetRecordResponse) -> Self {
        RecordRow {
            value: display_record_value(&record.value),
            ..Self::whole(record)
        }
    }
}

impl RecordRow {
    /// Build the row for a single record, whose whole value is the point.
    pub(crate) fn whole(record: &GetRecordResponse) -> Self {
        RecordRow {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: record.value.to_text(),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: record.zone_name.clone(),
        }
    }
}

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
    pub(crate) key_tag: u16,
    #[tabled(rename = "DNSKEY")]
    pub(crate) dnskey: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&DnssecKeyInfo> for DnssecKeyRow {
    /// Build a CLI table row from the DNSSEC key info.
    fn from(key: &DnssecKeyInfo) -> Self {
        DnssecKeyRow {
            id: key.id,
            role: key.role.to_string(),
            state: key.state.to_string(),
            state_changed_at: display_time(key.state_changed_at),
            eligible_at: display_option_time(&key.eligible_at),
            algorithm: key.algorithm.clone(),
            key_tag: key.key_tag,
            dnskey: key.dnskey.clone(),
            created_at: display_time(key.created_at),
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
    #[tabled(rename = "KEYS")]
    pub(crate) keys: String,
    #[tabled(rename = "VALIDITY")]
    pub(crate) validity: String,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: String,
    #[tabled(rename = "ZSK-LIFETIME")]
    pub(crate) zsk_lifetime: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetDnssecPolicyResponse> for DnssecPolicyRow {
    /// Build a CLI table row from the DNSSEC policy response.
    fn from(policy: &GetDnssecPolicyResponse) -> Self {
        DnssecPolicyRow {
            id: policy.id,
            name: policy.name.clone(),
            algorithm: policy.algorithm.clone(),
            denial: policy.denial.to_string(),
            keys: if policy.split_keys { "KSK/ZSK" } else { "CSK" }.to_string(),
            validity: format!("{}d", policy.signature_validity_days),
            refresh: format!("{}d", policy.signature_refresh_days),
            zsk_lifetime: if policy.zsk_lifetime_days == 0 {
                MISSING_CELL.to_string()
            } else {
                format!("{}d", policy.zsk_lifetime_days)
            },
            created_at: display_time(policy.created_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct SecondaryRow {
    #[tabled(rename = "ID")]
    pub(crate) id: SecondaryId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "ENABLED")]
    pub(crate) enabled: String,
    #[tabled(rename = "NOTIFY-KEY")]
    pub(crate) notify_key_name: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetSecondaryResponse> for SecondaryRow {
    /// Build a CLI table row from the secondary response.
    fn from(secondary: &GetSecondaryResponse) -> Self {
        SecondaryRow {
            id: secondary.id,
            name: secondary.name.clone(),
            address: secondary.address.clone(),
            enabled: display_yes_no(&secondary.enabled),
            notify_key_name: display_option(&secondary.notify_key_name),
            created_at: display_time(secondary.created_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct VersionRow {
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: Serial,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i32,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: i32,
    #[tabled(rename = "RETRY")]
    pub(crate) retry: i32,
    #[tabled(rename = "EXPIRE")]
    pub(crate) expire: i32,
    #[tabled(rename = "MINIMUM-TTL")]
    pub(crate) minimum_ttl: i32,
    #[tabled(rename = "SOURCE")]
    pub(crate) change_source: String,
    #[tabled(rename = "CHANGED-BY")]
    pub(crate) changed_by: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&ZoneVersionResponse> for VersionRow {
    /// Build a CLI table row from the zone version response.
    fn from(version: &ZoneVersionResponse) -> Self {
        VersionRow {
            serial: version.serial,
            mname: version.mname.clone(),
            rname: version.rname.clone(),
            default_ttl: i32::from(version.default_ttl),
            refresh: version.refresh,
            retry: version.retry,
            expire: version.expire,
            minimum_ttl: i32::from(version.minimum_ttl),
            change_source: version.change_source.to_string(),
            changed_by: display_option(&version.changed_by),
            created_at: display_time(version.created_at),
        }
    }
}

/// Table row for records reconstructed at a version serial (no database id).
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct VersionRecordRow {
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: Ttl,
    #[tabled(rename = "PRIORITY", display = "display_option")]
    pub(crate) priority: Option<i32>,
}

impl From<&VersionRecordResponse> for VersionRecordRow {
    /// Build a CLI table row from the version record response.
    fn from(record: &VersionRecordResponse) -> Self {
        VersionRecordRow {
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: display_record_value(&record.value),
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct RollbackSummaryRow {
    #[tabled(rename = "TARGET-SERIAL")]
    pub(crate) target_serial: u32,
    #[tabled(rename = "NEW-SERIAL")]
    pub(crate) new_serial: u32,
    #[tabled(rename = "APPLIED", display = "display_yes_no")]
    pub(crate) applied: bool,
    #[tabled(rename = "DRY-RUN", display = "display_yes_no")]
    pub(crate) dry_run: bool,
    #[tabled(rename = "ADDED")]
    pub(crate) added: u64,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: u64,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: u64,
    #[tabled(rename = "SOA-CHANGED")]
    pub(crate) soa_changed: bool,
}

impl From<&RollbackZoneResponse> for RollbackSummaryRow {
    /// Build a CLI table row from the zone rollback summary.
    fn from(response: &RollbackZoneResponse) -> Self {
        RollbackSummaryRow {
            target_serial: response.target_serial.as_u32(),
            new_serial: response.new_serial.as_u32(),
            applied: response.applied,
            dry_run: response.dry_run,
            added: response.summary.added,
            deleted: response.summary.deleted,
            unchanged: response.summary.unchanged,
            soa_changed: response.summary.soa_changed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct SecondaryStatusRow {
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "STATUS")]
    pub(crate) status: String,
    #[tabled(rename = "VISIBLE-SERIAL")]
    pub(crate) visible_serial: String,
    #[tabled(rename = "LAG")]
    pub(crate) lag: String,
    #[tabled(rename = "LAST-TRANSFER")]
    pub(crate) last_transfer: String,
}

impl SecondaryStatusRow {
    /// One row per secondary, with the lag behind the zone serial that its
    /// `status` was classified against.
    pub(crate) fn rows_from_status(status: &ZoneStatusResponse) -> Vec<Self> {
        status
            .secondaries
            .iter()
            .map(|secondary| Self::from_secondary(secondary, status.serial))
            .collect()
    }

    /// Build a table row from a secondary server's status.
    fn from_secondary(secondary: &SecondaryStatusResponse, zone_serial: Serial) -> Self {
        let detail = match secondary.error.as_deref() {
            Some(error) if secondary.is_unreachable() => {
                format!("{} ({})", secondary.status, error)
            }
            _ => secondary.status.to_string(),
        };
        SecondaryStatusRow {
            address: secondary.address.clone(),
            status: detail,
            visible_serial: display_option(&secondary.visible_serial),
            lag: secondary.visible_serial.map_or_else(
                || MISSING_CELL.to_string(),
                |serial| (i64::from(zone_serial.as_u32()) - i64::from(serial.as_u32())).to_string(),
            ),
            last_transfer: secondary
                .last_transfer
                .as_ref()
                .map_or_else(|| MISSING_CELL.to_string(), display_transfer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ImportSummaryRow {
    /// The counts describe the plan, which a rejected file never applies.
    #[tabled(rename = "APPLIED", display = "display_yes_no")]
    pub(crate) applied: bool,
    #[tabled(rename = "DRY-RUN", display = "display_yes_no")]
    pub(crate) dry_run: bool,
    #[tabled(rename = "PARSED")]
    pub(crate) parsed: u64,
    #[tabled(rename = "ADDED")]
    pub(crate) added: u64,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: u64,
    #[tabled(rename = "UPDATED")]
    pub(crate) updated: u64,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: u64,
    #[tabled(rename = "SKIPPED")]
    pub(crate) skipped: u64,
}

impl From<&ImportZoneResponse> for ImportSummaryRow {
    /// Build a CLI table row from the import result.
    fn from(response: &ImportZoneResponse) -> Self {
        let summary = &response.summary;
        ImportSummaryRow {
            applied: response.applied,
            dry_run: response.dry_run,
            parsed: summary.parsed,
            added: summary.added,
            deleted: summary.deleted,
            updated: summary.updated,
            unchanged: summary.unchanged,
            skipped: summary.skipped,
        }
    }
}

/// TOKEN is filled only from a create response, the one time the secret is shown.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TokenRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TokenId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TOKEN")]
    pub(crate) token: String,
    #[tabled(rename = "GLOBAL")]
    pub(crate) global: String,
    #[tabled(rename = "DESCRIPTION")]
    pub(crate) description: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
    #[tabled(rename = "EXPIRES-AT")]
    pub(crate) expires_at: String,
    #[tabled(rename = "LAST-USED-AT")]
    pub(crate) last_used_at: String,
}

impl From<&GetTokenResponse> for TokenRow {
    /// Build a CLI table row from the token response.
    fn from(token: &GetTokenResponse) -> Self {
        TokenRow {
            id: token.id,
            name: token.name.clone(),
            token: MISSING_CELL.to_string(),
            global: display_yes_no(&token.global),
            description: display_option(&token.description),
            created_at: display_time(token.created_at),
            expires_at: token
                .expires_at
                .map(display_time)
                .unwrap_or_else(|| "Never".to_string()),
            last_used_at: display_option_time(&token.last_used_at),
        }
    }
}

impl From<&CreatedTokenResponse> for TokenRow {
    /// Build a CLI table row from the newly created token.
    fn from(created: &CreatedTokenResponse) -> Self {
        TokenRow {
            token: created.secret.clone(),
            ..TokenRow::from(&created.token)
        }
    }
}

/// SECRET is filled from the create and get responses; a listing carries none.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TsigKeyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TsigKeyId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "ALGORITHM")]
    pub(crate) algorithm: String,
    #[tabled(rename = "SECRET")]
    pub(crate) secret: String,
    #[tabled(rename = "GLOBAL")]
    pub(crate) global: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetTsigKeyResponse> for TsigKeyRow {
    /// Build a CLI table row from the TSIG key response.
    fn from(key: &GetTsigKeyResponse) -> Self {
        TsigKeyRow {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm.clone(),
            secret: MISSING_CELL.to_string(),
            global: display_yes_no(&key.global),
            created_at: display_time(key.created_at),
        }
    }
}

impl From<&TsigKeyResponse> for TsigKeyRow {
    /// Build a CLI table row from the TSIG key response.
    fn from(key: &TsigKeyResponse) -> Self {
        TsigKeyRow {
            secret: key.secret.clone(),
            ..TsigKeyRow::from(&key.tsig_key)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TokenGrantRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TokenGrantId,
    #[tabled(rename = "TOKEN")]
    pub(crate) token_name: String,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "NAME-PATTERN")]
    pub(crate) record_name_pattern: String,
    #[tabled(rename = "RECORD-TYPES")]
    pub(crate) record_types: String,
    #[tabled(rename = "ACCESS")]
    pub(crate) access: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetTokenGrantResponse> for TokenGrantRow {
    /// Build a CLI table row from the token grant response.
    fn from(grant: &GetTokenGrantResponse) -> Self {
        TokenGrantRow {
            id: grant.id,
            token_name: grant.token_name.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            access: if grant.can_write {
                "read-write"
            } else {
                "read-only"
            }
            .to_string(),
            created_at: display_time(grant.created_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TsigGrantRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TsigGrantId,
    #[tabled(rename = "TSIG-KEY")]
    pub(crate) tsig_key_name: String,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "NAME-PATTERN")]
    pub(crate) record_name_pattern: String,
    #[tabled(rename = "RECORD-TYPES")]
    pub(crate) record_types: String,
    #[tabled(rename = "ACCESS")]
    pub(crate) access: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetTsigGrantResponse> for TsigGrantRow {
    /// Build a CLI table row from the TSIG grant response.
    fn from(grant: &GetTsigGrantResponse) -> Self {
        TsigGrantRow {
            id: grant.id,
            tsig_key_name: grant.tsig_key_name.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            access: if grant.can_write {
                "transfer+update"
            } else {
                "transfer-only"
            }
            .to_string(),
            created_at: display_time(grant.created_at),
        }
    }
}

/// One transfer Bindizr served a secondary, as `secondary transfers` lists
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TransferRow {
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "TRANSFER")]
    pub(crate) transfer: String,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: String,
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "AT")]
    pub(crate) at: String,
    #[tabled(rename = "ERROR")]
    pub(crate) error: String,
}

impl From<&TransferResponse> for TransferRow {
    /// Build a table row from one served transfer.
    fn from(transfer: &TransferResponse) -> Self {
        TransferRow {
            zone_name: transfer.zone_name.clone(),
            transfer: display_transfer_kind(transfer),
            serial: display_option(&transfer.serial),
            address: transfer.address.clone(),
            at: display_time(transfer.at),
            error: display_option(&transfer.error),
        }
    }
}
