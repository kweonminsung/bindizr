//! Secondary servers: one registry behind NOTIFY fan-out, the unsigned
//! transfer ACL, and the serial probes, so a server that hears a change is
//! also the one allowed to pull it.

use bindizr_core::dns::{
    address::{ParsedAddress, is_address_target},
    name::has_whitespace_or_control,
};
use chrono::Utc;

use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::secondary::Secondary,
    repository::RepositoryService,
    types::{GetSecondaryResponse, PageFilter, PaginatedResponse, UpdateSecondaryRequest},
};

/// The width of the `secondaries.name` and `secondaries.address` columns.
const MAX_SECONDARY_FIELD_LEN: usize = 255;

/// The port a `host` entry without one is registered with.
const DEFAULT_DNS_PORT: u16 = 53;

pub struct SecondaryService;

impl SecondaryService {
    /// Register a secondary by name and `host[:port]` address.
    pub async fn create(
        caller: &Caller,
        name: &str,
        address: &str,
    ) -> Result<Secondary, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let name = normalize_secondary_name(name)?;
        let address = normalize_secondary_address(address)?;

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

        RepositoryService::create_secondary(Secondary {
            id: 0,
            name,
            address,
            enabled: true,
            created_at: Utc::now(),
        })
        .await
    }

    /// List every secondary, disabled ones included.
    pub async fn list(
        caller: &Caller,
        page: PageFilter,
    ) -> Result<PaginatedResponse<GetSecondaryResponse>, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let secondaries = RepositoryService::list_secondaries().await?;
        PaginatedResponse::from_collection(
            secondaries
                .iter()
                .map(GetSecondaryResponse::from_secondary)
                .collect(),
            page.limit,
            page.offset,
        )
    }

    /// Fetch one secondary by name.
    pub async fn get(caller: &Caller, name: &str) -> Result<Secondary, ServiceError> {
        caller.authorize_global("manage secondaries")?;
        Self::lookup_by_name(name).await
    }

    /// Change a secondary's address or enabled flag.
    pub async fn update(
        caller: &Caller,
        name: &str,
        request: UpdateSecondaryRequest,
    ) -> Result<Secondary, ServiceError> {
        caller.authorize_global("manage secondaries")?;

        let name = normalize_secondary_name(name)?;
        let address = request
            .address
            .as_deref()
            .map(normalize_secondary_address)
            .transpose()?;
        if address.is_none() && request.enabled.is_none() {
            return Err(ServiceError::invalid_input(
                "nothing to update: give an address or enabled",
            ));
        }
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
                    ..secondary
                },
            )
            .await
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to update secondary").await
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
    let name = value.trim().to_lowercase();

    if name.is_empty() {
        return Err(ServiceError::invalid_input(
            "secondary name must not be empty",
        ));
    }
    if name.len() > MAX_SECONDARY_FIELD_LEN {
        return Err(ServiceError::invalid_input(format!(
            "secondary name must be {} characters or fewer",
            MAX_SECONDARY_FIELD_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ServiceError::invalid_input(
            "secondary name may contain only letters, digits, '-', '_', and '.'",
        ));
    }
    Ok(name)
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
