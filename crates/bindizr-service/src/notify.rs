use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use bindizr_core::config;

#[async_trait]
pub trait NotifySender: Send + Sync {
    async fn send_notify(&self, zone_name: Option<&str>) -> Result<(), String>;
}

static NOTIFY_SENDER: OnceLock<Arc<dyn NotifySender>> = OnceLock::new();

pub fn set_notify_sender(sender: Arc<dyn NotifySender>) -> Result<(), &'static str> {
    NOTIFY_SENDER
        .set(sender)
        .map_err(|_| "notify sender is already registered")
}

pub async fn send_notify(zone_name: Option<&str>) -> Result<(), String> {
    match NOTIFY_SENDER.get() {
        Some(sender) => sender.send_notify(zone_name).await,
        None => Err("notify sender is not registered".to_string()),
    }
}

pub async fn send_notify_after_update(zone_name: Option<&str>) -> Result<(), String> {
    if !config::get_bindizr_config().dns.notify_after_update {
        return Ok(());
    }

    send_notify(zone_name).await
}
