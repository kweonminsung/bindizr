use crate::socket::dto::DaemonResponse;
use crate::{api, serializer, socket};

const SHUTDOWN_DELAY_MS: u64 = 100;

pub fn shutdown() -> Result<DaemonResponse, String> {
    // Graceful termination
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(SHUTDOWN_DELAY_MS));

        serializer::shutdown();
        socket::server::shutdown();
        api::shutdown();

        std::process::exit(0);
    });

    Ok(DaemonResponse {
        message: "Daemon shutdown successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
