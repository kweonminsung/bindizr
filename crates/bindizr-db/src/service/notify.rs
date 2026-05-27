use std::{future::Future, pin::Pin, sync::OnceLock};

pub type NotifyFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
pub type NotifyHook = fn(Option<String>) -> NotifyFuture;

static NOTIFY_HOOK: OnceLock<NotifyHook> = OnceLock::new();

pub fn set_notify_hook(hook: NotifyHook) -> Result<(), &'static str> {
    NOTIFY_HOOK
        .set(hook)
        .map_err(|_| "notify hook is already registered")
}

pub async fn send_notify(zone_name: Option<&str>) -> Result<(), String> {
    match NOTIFY_HOOK.get() {
        Some(hook) => hook(zone_name.map(ToOwned::to_owned)).await,
        None => Ok(()),
    }
}
