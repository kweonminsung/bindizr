//! Table rows for CLI output, each built from the typed daemon response so
//! the column set is all this module decides.

use bindizr_service::types::{
    CreatedTokenResponse, DnssecKeyInfo, GetDnssecPolicyResponse, GetRecordResponse,
    GetTokenGrantResponse, GetTokenResponse, GetTsigGrantResponse, GetTsigKeyResponse,
    GetZoneResponse, ImportSummary, RecordValueRequest, RollbackZoneResponse,
    SecondaryStatusResponse, TsigKeyResponse, VersionRecordResponse, ZoneStatusResponse,
    ZoneVersionResponse,
};
use tabled::Tabled;

fn display_option_i32(opt: &Option<i32>) -> String {
    match opt {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.to_string()
}

fn display_option_text(opt: &Option<String>) -> String {
    opt.clone().unwrap_or_else(|| "-".to_string())
}

fn display_option_time(opt: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    opt.map_or_else(|| "-".to_string(), |at| at.to_rfc3339())
}

/// A record value as one table cell; TXT segments concatenate into the string
/// they encode.
fn value_text(value: &RecordValueRequest) -> String {
    match value {
        RecordValueRequest::String(value) => value.clone(),
        RecordValueRequest::Segments(segments) => segments.concat(),
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct ZoneRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i32,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: i32,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: i32,
    #[tabled(rename = "RETRY")]
    pub(crate) retry: i32,
    #[tabled(rename = "EXPIRE")]
    pub(crate) expire: i32,
    #[tabled(rename = "MINIMUM-TTL")]
    pub(crate) minimum_ttl: i32,
}

impl From<&GetZoneResponse> for ZoneRow {
    fn from(zone: &GetZoneResponse) -> Self {
        ZoneRow {
            id: zone.id,
            name: zone.name.clone(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: zone.default_ttl,
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct RecordRow {
    #[tabled(rename = "ID", display = "display_option_i32")]
    pub(crate) id: Option<i32>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: i32,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    pub(crate) priority: Option<i32>,
    #[tabled(rename = "ZONE-ID")]
    pub(crate) zone_id: i32,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
}

impl From<&GetRecordResponse> for RecordRow {
    fn from(record: &GetRecordResponse) -> Self {
        RecordRow {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: value_text(&record.value),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: record.zone_name.clone(),
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct DnssecKeyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
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
    pub(crate) key_tag: i32,
    #[tabled(rename = "DNSKEY")]
    pub(crate) dnskey: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&DnssecKeyInfo> for DnssecKeyRow {
    fn from(key: &DnssecKeyInfo) -> Self {
        DnssecKeyRow {
            id: key.id,
            role: key.role.clone(),
            state: key.state.clone(),
            state_changed_at: key.state_changed_at.to_rfc3339(),
            eligible_at: display_option_time(&key.eligible_at),
            algorithm: key.algorithm.clone(),
            key_tag: key.key_tag,
            dnskey: key.dnskey.clone(),
            created_at: key.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct DnssecPolicyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
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
    #[tabled(rename = "PUBLISH-WAIT")]
    pub(crate) publish_wait: String,
    #[tabled(rename = "RETIRE-WAIT")]
    pub(crate) retire_wait: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetDnssecPolicyResponse> for DnssecPolicyRow {
    fn from(policy: &GetDnssecPolicyResponse) -> Self {
        DnssecPolicyRow {
            id: policy.id,
            name: policy.name.clone(),
            algorithm: policy.algorithm.clone(),
            denial: policy.denial.to_uppercase(),
            keys: if policy.split_keys { "KSK/ZSK" } else { "CSK" }.to_string(),
            validity: format!("{}d", policy.signature_validity_days),
            refresh: format!("{}d", policy.signature_refresh_days),
            zsk_lifetime: if policy.zsk_lifetime_days == 0 {
                "-".to_string()
            } else {
                format!("{}d", policy.zsk_lifetime_days)
            },
            publish_wait: format!("{}s", policy.rollover_publish_holddown_secs),
            retire_wait: format!("{}s", policy.rollover_retire_holddown_secs),
            created_at: policy.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct VersionRow {
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: i32,
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
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&ZoneVersionResponse> for VersionRow {
    fn from(version: &ZoneVersionResponse) -> Self {
        VersionRow {
            serial: version.serial,
            mname: version.mname.clone(),
            rname: version.rname.clone(),
            default_ttl: version.default_ttl,
            refresh: version.refresh,
            retry: version.retry,
            expire: version.expire,
            minimum_ttl: version.minimum_ttl,
            created_at: version.created_at.to_rfc3339(),
        }
    }
}

/// Table row for records reconstructed at a version serial (no database id).
#[derive(Debug, Tabled)]
pub(crate) struct VersionRecordRow {
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: i32,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    pub(crate) priority: Option<i32>,
}

impl From<&VersionRecordResponse> for VersionRecordRow {
    fn from(record: &VersionRecordResponse) -> Self {
        VersionRecordRow {
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: value_text(&record.value),
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct RollbackSummaryRow {
    #[tabled(rename = "TARGET-SERIAL")]
    pub(crate) target_serial: i32,
    #[tabled(rename = "NEW-SERIAL")]
    pub(crate) new_serial: i32,
    #[tabled(rename = "APPLIED")]
    pub(crate) applied: bool,
    #[tabled(rename = "DRY-RUN")]
    pub(crate) dry_run: bool,
    #[tabled(rename = "ADDED")]
    pub(crate) records_added: usize,
    #[tabled(rename = "DELETED")]
    pub(crate) records_deleted: usize,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) records_unchanged: usize,
    #[tabled(rename = "SOA-CHANGED")]
    pub(crate) soa_changed: bool,
}

impl From<&RollbackZoneResponse> for RollbackSummaryRow {
    fn from(response: &RollbackZoneResponse) -> Self {
        RollbackSummaryRow {
            target_serial: response.target_serial,
            new_serial: response.new_serial,
            applied: response.applied,
            dry_run: response.dry_run,
            records_added: response.summary.records_added,
            records_deleted: response.summary.records_deleted,
            records_unchanged: response.summary.records_unchanged,
            soa_changed: response.summary.soa_changed,
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct SecondaryStatusRow {
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "STATUS")]
    pub(crate) status: String,
    #[tabled(rename = "VISIBLE-SERIAL")]
    pub(crate) visible_serial: String,
    #[tabled(rename = "LAG")]
    pub(crate) lag: String,
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

    fn from_secondary(secondary: &SecondaryStatusResponse, zone_serial: i32) -> Self {
        let detail = match secondary.error.as_deref() {
            Some(error) if secondary.is_unreachable() => {
                format!("{} ({})", secondary.status, error)
            }
            _ => secondary.status.clone(),
        };
        SecondaryStatusRow {
            address: secondary.address.clone(),
            status: detail,
            visible_serial: secondary
                .visible_serial
                .map_or_else(|| "-".to_string(), |serial| serial.to_string()),
            lag: secondary.visible_serial.map_or_else(
                || "-".to_string(),
                |serial| (i64::from(zone_serial) - serial).to_string(),
            ),
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct ImportSummaryRow {
    #[tabled(rename = "PARSED")]
    pub(crate) parsed: usize,
    #[tabled(rename = "ADDED")]
    pub(crate) added: usize,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: usize,
    #[tabled(rename = "UPDATED")]
    pub(crate) updated: usize,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: usize,
    #[tabled(rename = "SKIPPED")]
    pub(crate) skipped: usize,
}

impl From<&ImportSummary> for ImportSummaryRow {
    fn from(summary: &ImportSummary) -> Self {
        ImportSummaryRow {
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
#[derive(Debug, Tabled)]
pub(crate) struct TokenRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
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
    fn from(token: &GetTokenResponse) -> Self {
        TokenRow {
            id: token.id,
            name: token.name.clone(),
            token: display_option_text(&None),
            global: yes_no(token.global),
            description: display_option_text(&token.description),
            created_at: token.created_at.to_rfc3339(),
            expires_at: token
                .expires_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "Never".to_string()),
            last_used_at: display_option_time(&token.last_used_at),
        }
    }
}

impl From<&CreatedTokenResponse> for TokenRow {
    fn from(created: &CreatedTokenResponse) -> Self {
        TokenRow {
            token: created.secret.clone(),
            ..TokenRow::from(&created.token)
        }
    }
}

/// SECRET is filled from the create and get responses; a listing carries none.
#[derive(Debug, Tabled)]
pub(crate) struct TsigKeyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
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
    fn from(key: &GetTsigKeyResponse) -> Self {
        TsigKeyRow {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm.clone(),
            secret: display_option_text(&None),
            global: yes_no(key.global),
            created_at: key.created_at.to_rfc3339(),
        }
    }
}

impl From<&TsigKeyResponse> for TsigKeyRow {
    fn from(key: &TsigKeyResponse) -> Self {
        TsigKeyRow {
            secret: key.secret.clone(),
            ..TsigKeyRow::from(&key.tsig_key)
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct TokenGrantRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
    #[tabled(rename = "TOKEN")]
    pub(crate) api_token: String,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "NAME-PATTERN")]
    pub(crate) record_name_pattern: String,
    #[tabled(rename = "RECORD-TYPES")]
    pub(crate) record_types: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetTokenGrantResponse> for TokenGrantRow {
    fn from(grant: &GetTokenGrantResponse) -> Self {
        TokenGrantRow {
            id: grant.id,
            api_token: grant.api_token.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            created_at: grant.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Tabled)]
pub(crate) struct TsigGrantRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
    #[tabled(rename = "TSIG-KEY")]
    pub(crate) tsig_key: String,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "NAME-PATTERN")]
    pub(crate) record_name_pattern: String,
    #[tabled(rename = "RECORD-TYPES")]
    pub(crate) record_types: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&GetTsigGrantResponse> for TsigGrantRow {
    fn from(grant: &GetTsigGrantResponse) -> Self {
        TsigGrantRow {
            id: grant.id,
            tsig_key: grant.tsig_key.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            created_at: grant.created_at.to_rfc3339(),
        }
    }
}
