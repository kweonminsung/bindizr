use crate::{Context, db, error::ServiceError, transaction};

/// Refuse to start while a stored zone holds the configured catalog zone
/// name, which a write would be rejected for taking.
pub async fn validate_catalog_zone_name(cx: &Context) -> Result<(), ServiceError> {
    let name = &cx.config().dns.catalog_zone_name;
    if db::zone::get_by_name(cx.db(), name).await?.is_some() {
        return Err(ServiceError::zone_conflict(format!(
            "zone '{}' has the name dns.catalog_zone_name gives the catalog; rename either one",
            name
        )));
    }
    Ok(())
}

/// Advance the catalog zone serial when its content `digest` has changed;
/// a no-op otherwise.
pub async fn advance_catalog_serial(
    cx: &Context,
    name: &str,
    digest: &str,
    base_serial: i32,
) -> Result<i32, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "Failed to update catalog state").await?;

    let apply_result = db::catalog_zone::upsert_tx(&mut tx, name, digest, base_serial)
        .await
        .map_err(ServiceError::from);

    transaction::finish_tx(tx, apply_result, "Failed to update catalog state").await
}
