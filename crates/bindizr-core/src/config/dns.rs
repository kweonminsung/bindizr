//! DNS serving, transfer, notification, import, and zone defaults.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, TlsFiles, default_listen_addr, validate_tls_pair};
use crate::dns;
use crate::dns::name::ZoneName;
use crate::dns::{SoaInterval, Ttl};

/// The longest idle timeout the edns-tcp-keepalive option carries.
const MAX_TCP_IDLE_TIMEOUT_SECS: u64 = 6553;

/// DNS server settings; the sub-tables hold the import client, NOTIFY,
/// nsupdate, the TLS listener, transfers, and zone defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    #[serde(default = "default_dns_listen_port")]
    pub listen_port: u16,
    /// Virtual RFC 9432 catalog zone name; primaries sharing a secondary need distinct names.
    #[serde(default = "default_catalog_zone_name")]
    pub catalog_zone_name: ZoneName,
    /// Seconds between scheduler passes for signing, rollover, and history pruning.
    /// 0 disables this instance; at least one instance must run the scheduler.
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    /// Seconds a TCP or TLS connection may sit idle between queries;
    /// advertised as the edns-tcp-keepalive timeout (RFC 7828, Section 3.3.2).
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    /// Connections served at once on each of the TCP and TLS listeners; the
    /// rest wait in the accept backlog.
    #[serde(default = "default_tcp_max_connections")]
    pub tcp_max_connections: usize,
    #[serde(default)]
    pub import: ImportConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub nsupdate: NsupdateConfig,
    #[serde(default)]
    pub tls: DnsTlsConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
    #[serde(default)]
    pub zone_defaults: ZoneDefaultsConfig,
}

impl DnsConfig {
    /// Return whether a DNS question's decoded labels name this instance's catalog (RFC 4343).
    pub fn is_catalog_zone(&self, zone_name: &str) -> bool {
        ZoneName::parse(zone_name)
            .is_ok_and(|canonical_zone_name| canonical_zone_name == self.catalog_zone_name)
    }

    /// Return how long a TCP or TLS connection may sit idle between queries.
    pub fn tcp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_idle_timeout_secs)
    }

    /// Validate the DNS configuration fields.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let catalog_wire = self
            .catalog_zone_name
            .to_wire()
            .map_err(ConfigError::CatalogZoneName)?;

        if catalog_wire.len() > dns::MAX_CATALOG_ZONE_WIRE_LEN {
            return Err(ConfigError::CatalogZoneTooLong {
                max_wire_len: dns::MAX_CATALOG_ZONE_WIRE_LEN,
            });
        }
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "dns" });
        }

        // RFC 7858, Section 3.1: servers "MUST NOT use port 853 to transport
        // cleartext DNS messages".
        if self.listen_port == 853 {
            return Err(ConfigError::PortReserved {
                section: "dns",
                port: 853,
                reserved_for: "DNS over TLS",
            });
        }

        // The idle timeout must fit the keepalive option's 16-bit deciseconds.
        if !(1..=MAX_TCP_IDLE_TIMEOUT_SECS).contains(&self.tcp_idle_timeout_secs) {
            return Err(ConfigError::OutOfRange {
                key: "dns.tcp_idle_timeout_secs",
                min: 1,
                max: MAX_TCP_IDLE_TIMEOUT_SECS,
            });
        }
        if self.tcp_max_connections == 0 {
            return Err(ConfigError::Zero {
                key: "dns.tcp_max_connections",
            });
        }

        self.tls.validate()?;
        self.import.validate()?;

        // Refusing plain transfers with no TLS listener would refuse them all.
        if self.transfer.require_tls && self.tls.tls_files().is_none() {
            return Err(ConfigError::TransferRequiresTlsListener);
        }

        // A zone without its own timers inherits these; unlike a requested
        // value, which may be zero, a default must be positive.
        let defaults = &self.zone_defaults;

        for (field, secs) in [
            ("refresh", defaults.refresh.as_secs()),
            ("retry", defaults.retry.as_secs()),
            ("expire", defaults.expire.as_secs()),
            ("minimum_ttl", defaults.minimum_ttl.as_secs()),
        ] {
            if secs == 0 {
                return Err(ConfigError::ZoneDefaultZero { field });
            }
        }

        Ok(())
    }
}

impl Default for DnsConfig {
    /// Build the default DNS listener and zone-management settings.
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_dns_listen_port(),
            catalog_zone_name: default_catalog_zone_name(),
            scheduler_interval_secs: default_scheduler_interval_secs(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            tcp_max_connections: default_tcp_max_connections(),
            import: ImportConfig::default(),
            notify: NotifyConfig::default(),
            nsupdate: NsupdateConfig::default(),
            tls: DnsTlsConfig::default(),
            transfer: TransferConfig::default(),
            zone_defaults: ZoneDefaultsConfig::default(),
        }
    }
}

/// Return the default DNS port, leaving port 53 available to a secondary.
fn default_dns_listen_port() -> u16 {
    5300
}

/// When NOTIFY reaches the secondaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// NOTIFY coalescing window in milliseconds; queued sends follow the write response.
    /// Capped at SOA REFRESH from enqueue time; `0` sends every change before responding.
    #[serde(default)]
    pub batch_ms: u64,
    #[serde(default = "default_notify_retries")]
    pub retries: u32,
    /// Seconds to wait for each NOTIFY, SOA probe, and parent-NS query.
    #[serde(default = "default_notify_timeout_secs")]
    pub timeout_secs: u64,
}

impl NotifyConfig {
    /// Return how long one NOTIFY, probe, or resolution waits for its answer.
    pub fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

impl Default for NotifyConfig {
    /// Build the default NOTIFY settings.
    fn default() -> Self {
        Self {
            batch_ms: 0,
            retries: default_notify_retries(),
            timeout_secs: default_notify_timeout_secs(),
        }
    }
}

/// Zone transfers as bindizr serves them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    /// Record budget for transfer caches keyed by zone version, evicting least-recently-used zones.
    /// Oversized zones are served uncached; `0` disables caching.
    #[serde(default = "default_transfer_cache_max_records")]
    pub cache_max_records: u64,
    /// Refuse AXFR and IXFR over plain TCP and UDP (RFC 9103, Section 11);
    /// SOA queries keep answering. Needs `[dns.tls]`.
    #[serde(default)]
    pub require_tls: bool,
}

impl Default for TransferConfig {
    /// Build the default transfer settings.
    fn default() -> Self {
        Self {
            cache_max_records: default_transfer_cache_max_records(),
            require_tls: false,
        }
    }
}

/// nsupdate (RFC 2136).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NsupdateConfig {
    /// Require a TSIG signature on every update; `false` admits anyone.
    #[serde(default = "default_nsupdate_tsig_required")]
    pub tsig_required: bool,
}

impl Default for NsupdateConfig {
    /// Build the default nsupdate settings: signed updates only.
    fn default() -> Self {
        Self {
            tsig_required: default_nsupdate_tsig_required(),
        }
    }
}

/// Return the default nsupdate TSIG requirement.
fn default_nsupdate_tsig_required() -> bool {
    true
}

/// Return the default idle timeout between queries on a connection.
fn default_tcp_idle_timeout_secs() -> u64 {
    30
}

/// Return the default number of connections served at once per listener.
fn default_tcp_max_connections() -> usize {
    128
}

/// `zone import --from-server`: the AXFR bindizr pulls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportConfig {
    /// Seconds the whole transfer may take, resolution included.
    #[serde(default = "default_import_timeout_secs")]
    pub timeout_secs: u64,
    /// Records a pulled zone may hold; a larger one is refused.
    #[serde(default = "default_import_max_records")]
    pub max_records: usize,
}

impl ImportConfig {
    /// Return how long the whole transfer may take.
    pub fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Validate the import bounds.
    fn validate(self) -> Result<(), ConfigError> {
        if self.timeout_secs == 0 {
            return Err(ConfigError::Zero {
                key: "dns.import.timeout_secs",
            });
        }
        if self.max_records == 0 {
            return Err(ConfigError::Zero {
                key: "dns.import.max_records",
            });
        }

        Ok(())
    }
}

impl Default for ImportConfig {
    /// Build the default import bounds.
    fn default() -> Self {
        Self {
            timeout_secs: default_import_timeout_secs(),
            max_records: default_import_max_records(),
        }
    }
}

/// Return the default deadline of a pulled transfer.
fn default_import_timeout_secs() -> u64 {
    30
}

/// Return the default record limit of a pulled zone.
fn default_import_max_records() -> usize {
    200_000
}

/// Zone transfers over TLS (XoT, RFC 9103): a second TCP listener on
/// `dns.listen_addr`, served while both PEM files are set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTlsConfig {
    /// 853 is the port DNS over TLS registers (RFC 7858, Section 3.1).
    #[serde(default = "default_dns_tls_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

impl DnsTlsConfig {
    /// Return the certificate and key to serve XoT with, or `None` while the TLS
    /// listener is off.
    pub fn tls_files(&self) -> Option<TlsFiles<'_>> {
        Some(TlsFiles {
            cert_file: self.cert_file.as_deref()?,
            key_file: self.key_file.as_deref()?,
        })
    }

    /// Validate the TLS listener fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "dns.tls" });
        }

        // RFC 7858, Section 3.1: DNS over TLS "MUST NOT be port 53".
        if self.listen_port == 53 {
            return Err(ConfigError::PortReserved {
                section: "dns.tls",
                port: 53,
                reserved_for: "cleartext DNS",
            });
        }

        // Half a pair would leave the listener off on a port the operator
        // means to serve, which no later error would reveal.
        validate_tls_pair(
            "dns.tls",
            self.cert_file.as_deref(),
            self.key_file.as_deref(),
        )
    }
}

impl Default for DnsTlsConfig {
    /// Build the default TLS listener settings: the registered port, and no
    /// certificate, so the listener stays off.
    fn default() -> Self {
        Self {
            listen_port: default_dns_tls_listen_port(),
            cert_file: None,
            key_file: None,
        }
    }
}

/// Return the default DNS over TLS listen port.
fn default_dns_tls_listen_port() -> u16 {
    853
}

/// What a zone takes when its creation request leaves a field out. Only the
/// creation reads these: afterwards the values are the zone's own columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneDefaultsConfig {
    #[serde(default = "default_zone_ttl")]
    pub ttl: Ttl,
    /// Short refresh/retry intervals limit staleness when NOTIFY is lost.
    #[serde(default = "default_zone_refresh")]
    pub refresh: SoaInterval,
    #[serde(default = "default_zone_retry")]
    pub retry: SoaInterval,
    #[serde(default = "default_zone_expire")]
    pub expire: SoaInterval,
    #[serde(default = "default_zone_minimum_ttl")]
    pub minimum_ttl: Ttl,
}

impl Default for ZoneDefaultsConfig {
    /// Build the default zone settings.
    fn default() -> Self {
        Self {
            ttl: default_zone_ttl(),
            refresh: default_zone_refresh(),
            retry: default_zone_retry(),
            expire: default_zone_expire(),
            minimum_ttl: default_zone_minimum_ttl(),
        }
    }
}

/// Return the default zone TTL setting.
fn default_zone_ttl() -> Ttl {
    Ttl::from_secs(3600)
}

/// Return the default zone refresh setting.
fn default_zone_refresh() -> SoaInterval {
    SoaInterval::from_secs(300)
}

/// Return the default zone retry setting.
fn default_zone_retry() -> SoaInterval {
    SoaInterval::from_secs(60)
}

/// Return the default zone expire setting.
fn default_zone_expire() -> SoaInterval {
    SoaInterval::from_secs(3_600_000)
}

/// Return the default zone minimum TTL setting.
fn default_zone_minimum_ttl() -> Ttl {
    Ttl::from_secs(86400)
}

/// Return the default scheduler interval setting: plenty next to the
/// day-scale windows a pass enforces.
fn default_scheduler_interval_secs() -> u64 {
    3600
}

/// Return the default transfer cache max records setting.
fn default_transfer_cache_max_records() -> u64 {
    500_000
}

/// Return the default notify retries setting.
fn default_notify_retries() -> u32 {
    3
}

/// Return the default notify timeout secs setting.
fn default_notify_timeout_secs() -> u64 {
    3
}

/// Return the default catalog zone name.
fn default_catalog_zone_name() -> ZoneName {
    // RFC 9432, Section 3 leaves the name to the operator; this one says which
    // primary a secondary is holding the catalog of.
    ZoneName::parse("catalog.bindizr").expect("the default catalog zone name is a valid zone name")
}
