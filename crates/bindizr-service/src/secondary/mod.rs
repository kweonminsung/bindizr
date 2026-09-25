//! Secondary servers: one registry behind NOTIFY fan-out, the unsigned
//! transfer ACL, and the serial probes, so a server that hears a change is
//! also the one allowed to pull it.

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use bindizr_core::{
    config::bindizr_config,
    dns::{
        address::{ParsedAddress, is_address_target, loopback_if_unspecified},
        name::has_whitespace_or_control,
        tsig::TsigSigningKey,
    },
};
use chrono::Utc;

use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dns_client::{notify, probe, resolve_address_entry},
    error::ServiceError,
    identifier::normalize_identifier,
    model::{secondary::Secondary, tsig_key::TsigKey},
    repository::RepositoryService,
    tsig_key::TsigKeyService,
    types::{
        GetSecondaryResponse, PageFilter, PaginatedResponse, SecondaryCheckResponse,
        UpdateSecondaryRequest,
    },
};

/// The width of the `secondaries.name` and `secondaries.address` columns.
const MAX_SECONDARY_FIELD_LEN: usize = 255;

/// The port a `host` entry without one is registered with.
const DEFAULT_DNS_PORT: u16 = 53;

pub struct SecondaryService;

impl SecondaryService {
    /// Register a secondary by name and `host[:port]` address; with
    /// `notify_key`, NOTIFY to it is signed with that TSIG key.
    pub async fn create(
        caller: &Caller,
        name: &str,
        address: &str,
        notify_key: Option<&str>,
    ) -> Result<GetSecondaryResponse, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let name = normalize_secondary_name(name)?;
        let address = normalize_secondary_address(address)?;
        // Unlocked read to learn the FK target; the constraint backstops.
        let notify_key = match notify_key {
            Some(key_name) => Some(TsigKeyService::lookup_by_name(key_name).await?),
            None => None,
        };

        // Friendly pre-checks; the UNIQUE backstops cover the race.
        if RepositoryService::get_secondary_by_name(&name)
            .await?
            .is_some()
        {
            return Err(ServiceError::secondary_conflict(format!(
                "Secondary with name '{}' already exists",
                name
            )));
        }
        if let Some(other) = RepositoryService::get_secondary_by_address(&address).await? {
            return Err(ServiceError::secondary_conflict(format!(
                "Secondary with address '{}' already exists (name '{}')",
                address, other.name
            )));
        }

        let secondary = RepositoryService::create_secondary(Secondary {
            id: 0,
            name,
            address,
            enabled: true,
            notify_tsig_key_id: notify_key.as_ref().map(|key| key.id),
            created_at: Utc::now(),
        })
        .await?;
        Ok(GetSecondaryResponse::from_secondary(
            &secondary,
            notify_key.as_ref().map(|key| key.name.as_str()),
        ))
    }

    /// List every secondary, disabled ones included.
    pub async fn list(
        caller: &Caller,
        page: PageFilter,
    ) -> Result<PaginatedResponse<GetSecondaryResponse>, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let secondaries = RepositoryService::list_secondaries().await?;
        // One statement names every key rather than one per secondary.
        let key_names: HashMap<i32, String> = RepositoryService::list_tsig_keys()
            .await?
            .into_iter()
            .map(|key| (key.id, key.name))
            .collect();
        PaginatedResponse::from_collection(
            secondaries
                .iter()
                .map(|secondary| {
                    GetSecondaryResponse::from_secondary(
                        secondary,
                        secondary
                            .notify_tsig_key_id
                            .and_then(|id| key_names.get(&id))
                            .map(String::as_str),
                    )
                })
                .collect(),
            page.limit,
            page.offset,
        )
    }

    /// Fetch one secondary by name.
    pub async fn get(caller: &Caller, name: &str) -> Result<GetSecondaryResponse, ServiceError> {
        caller.authorize_global("manage secondaries")?;
        let secondary = Self::lookup_by_name(name).await?;
        Self::to_response(secondary).await
    }

    /// Change a secondary's address, enabled flag, or NOTIFY key; an empty
    /// key name sends NOTIFY unsigned again.
    pub async fn update(
        caller: &Caller,
        name: &str,
        request: UpdateSecondaryRequest,
    ) -> Result<GetSecondaryResponse, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let name = normalize_secondary_name(name)?;
        let address = request
            .address
            .as_deref()
            .map(normalize_secondary_address)
            .transpose()?;
        if address.is_none() && request.enabled.is_none() && request.notify_key_name.is_none() {
            return Err(ServiceError::invalid_input(
                "nothing to update: give an address, enabled, or notify_key_name",
            ));
        }
        // Unlocked read to learn the FK target; the constraint backstops.
        let notify_key: Option<Option<TsigKey>> = match request.notify_key_name.as_deref() {
            None => None,
            Some("") => Some(None),
            Some(key_name) => Some(Some(TsigKeyService::lookup_by_name(key_name).await?)),
        };
        // Friendly pre-check; the UNIQUE(address) backstop covers the race.
        if let Some(address) = &address
            && let Some(other) = RepositoryService::get_secondary_by_address(address).await?
            && other.name != name
        {
            return Err(ServiceError::secondary_conflict(format!(
                "Secondary with address '{}' already exists (name '{}')",
                address, other.name
            )));
        }

        // Read and write under the row lock, or two partial updates would
        // each restore the field the other changed.
        let mut tx = RepositoryService::begin_tx("failed to update secondary").await?;
        let result = async {
            let secondary =
                RepositoryService::get_secondary_by_name_tx(&mut tx, &name, LockLevel::Exclusive)
                    .await?
                    .ok_or_else(|| ServiceError::secondary_not_found(&name))?;

            RepositoryService::update_secondary_tx(
                &mut tx,
                Secondary {
                    address: address.unwrap_or_else(|| secondary.address.clone()),
                    enabled: request.enabled.unwrap_or(secondary.enabled),
                    notify_tsig_key_id: match &notify_key {
                        Some(key) => key.as_ref().map(|key| key.id),
                        None => secondary.notify_tsig_key_id,
                    },
                    ..secondary
                },
            )
            .await
        }
        .await;
        let secondary =
            RepositoryService::finish_tx(tx, result, "failed to update secondary").await?;
        Self::to_response(secondary).await
    }

    /// Check one secondary, enabled or not: resolve its address, compare the
    /// catalog zone serial it serves with the one Bindizr's own listener
    /// serves, and send it a NOTIFY for the catalog zone.
    pub async fn check(
        caller: &Caller,
        name: &str,
    ) -> Result<SecondaryCheckResponse, ServiceError> {
        caller.authorize_global("manage secondaries")?;
        let secondary = Self::lookup_by_name(name).await?;

        let config = bindizr_config();
        let catalog_zone = config.dns.catalog_zone_name.clone();
        let timeout = Duration::from_secs(config.dns.notify.timeout_secs);
        // The listener's serial is the reference: it reflects the catalog's
        // current membership, which a stored serial would not.
        let dns_addr = SocketAddr::new(
            loopback_if_unspecified(config.dns.listen_addr),
            config.dns.listen_port,
        );
        let (catalog_serial, listener_error) =
            match probe::probe_server(dns_addr, &catalog_zone, timeout).await {
                Ok(serial) => (Some(serial), None),
                Err(e) => (None, Some(format!("{}: {}", dns_addr, e))),
            };

        let (addresses, resolve_error) =
            match resolve_address_entry(&secondary.address, timeout).await {
                Ok(addrs) => (addrs.iter().map(ToString::to_string).collect(), None),
                Err(e) => (Vec::new(), Some(e)),
            };
        let catalog = probe::probe_secondary(&catalog_zone, &secondary, catalog_serial)
            .await
            .map_err(ServiceError::internal)?;
        let notifies = notify::send_notify_to_secondary(&catalog_zone, &secondary)
            .await
            .map_err(ServiceError::internal)?;

        Ok(SecondaryCheckResponse {
            secondary: Self::to_response(secondary).await?,
            addresses,
            resolve_error,
            catalog_zone_name: catalog_zone,
            catalog_serial,
            listener_error,
            catalog,
            notifies,
        })
    }

    /// Delete a secondary by name.
    pub async fn delete(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let secondary = Self::lookup_by_name(name).await?;
        RepositoryService::delete_secondary(secondary.id).await
    }

    /// The enabled secondaries, for the DNS plane, which takes no caller.
    /// Read per use, so a change takes effect on the next NOTIFY or transfer.
    pub async fn list_enabled() -> Result<Vec<Secondary>, ServiceError> {
        Ok(RepositoryService::list_secondaries()
            .await?
            .into_iter()
            .filter(|secondary| secondary.enabled)
            .collect())
    }

    /// The key a secondary's NOTIFY is signed with, ready to sign; `None`
    /// for one notified unsigned. The FK keeps a referenced key present.
    pub(crate) async fn notify_signing_key(
        secondary: &Secondary,
    ) -> Result<Option<TsigSigningKey>, ServiceError> {
        match Self::notify_key(secondary).await? {
            Some(key) => key.to_domain_key().map(Some).map_err(|e| {
                ServiceError::internal(format!("NOTIFY key '{}' is unusable: {:?}", key.name, e))
            }),
            None => Ok(None),
        }
    }

    /// The stored key a secondary's NOTIFY is signed with, if any.
    async fn notify_key(secondary: &Secondary) -> Result<Option<TsigKey>, ServiceError> {
        match secondary.notify_tsig_key_id {
            Some(id) => Ok(Some(
                RepositoryService::get_tsig_key(id)
                    .await?
                    .ok_or_else(|| ServiceError::internal(format!("TSIG key {} is missing", id)))?,
            )),
            None => Ok(None),
        }
    }

    /// The API form of a secondary, naming its NOTIFY key.
    async fn to_response(secondary: Secondary) -> Result<GetSecondaryResponse, ServiceError> {
        let key = Self::notify_key(&secondary).await?;
        Ok(GetSecondaryResponse::from_secondary(
            &secondary,
            key.as_ref().map(|key| key.name.as_str()),
        ))
    }

    /// Fetch one secondary by name, unchecked.
    pub(crate) async fn lookup_by_name(name: &str) -> Result<Secondary, ServiceError> {
        let name = normalize_secondary_name(name)?;
        RepositoryService::get_secondary_by_name(&name)
            .await?
            .ok_or_else(|| ServiceError::secondary_not_found(&name))
    }
}

/// Lowercased so one name means one secondary on every backend; a plain
/// identifier, since it travels in URL paths.
pub(crate) fn normalize_secondary_name(value: &str) -> Result<String, ServiceError> {
    normalize_identifier(value, "secondary name", MAX_SECONDARY_FIELD_LEN)
}

/// A `host[:port]` entry in its stored form, the port spelled out and a
/// hostname lowercased, so one server has one row under UNIQUE(address).
pub(crate) fn normalize_secondary_address(value: &str) -> Result<String, ServiceError> {
    let address = value.trim();

    if address.is_empty() {
        return Err(ServiceError::invalid_input(
            "secondary address must not be empty",
        ));
    }
    if has_whitespace_or_control(address) || !is_address_target(address) {
        return Err(ServiceError::invalid_input(format!(
            "secondary address '{}' must be host[:port] with a numeric port",
            address
        )));
    }
    let address = match ParsedAddress::parse(address, DEFAULT_DNS_PORT) {
        ParsedAddress::SocketAddr(addr) => addr.to_string(),
        ParsedAddress::HostPort(host_port) => host_port.to_ascii_lowercase(),
    };
    if address.len() > MAX_SECONDARY_FIELD_LEN {
        return Err(ServiceError::invalid_input(format!(
            "secondary address must be {} characters or fewer",
            MAX_SECONDARY_FIELD_LEN
        )));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_secondary_name` lowercases and trims.
    #[test]
    fn normalize_secondary_name_lowercases_and_trims() {
        assert_eq!(
            normalize_secondary_name("  NS2.Example ").unwrap(),
            "ns2.example"
        );
    }

    /// Verify that `normalize_secondary_name` rejects a name that is not a plain identifier.
    #[test]
    fn normalize_secondary_name_rejects_a_name_that_is_not_a_plain_identifier() {
        for name in ["", "ns 2", "ns2/eu", &"n".repeat(256)] {
            let err = normalize_secondary_name(name).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{name:?}");
        }
    }

    /// Verify that `normalize_secondary_address` spells the port out and lowercases a hostname.
    #[test]
    fn normalize_secondary_address_spells_the_port_out_and_lowercases_a_hostname() {
        assert_eq!(
            normalize_secondary_address(" NS2.Example.net ").unwrap(),
            "ns2.example.net:53"
        );
        assert_eq!(
            normalize_secondary_address("192.0.2.7").unwrap(),
            "192.0.2.7:53"
        );
        assert_eq!(
            normalize_secondary_address("2001:db8::7").unwrap(),
            "[2001:db8::7]:53"
        );
        assert_eq!(
            normalize_secondary_address("[2001:db8::7]:5300").unwrap(),
            "[2001:db8::7]:5300"
        );
    }

    /// Verify that `normalize_secondary_address` rejects an entry that is not an address target.
    #[test]
    fn normalize_secondary_address_rejects_an_entry_that_is_not_an_address_target() {
        for address in ["", "not a host", "ns2.example.net:port", "192.0.2.7:0"] {
            let err = normalize_secondary_address(address).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{address:?}");
        }
    }
}
