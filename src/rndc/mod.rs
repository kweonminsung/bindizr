use crate::log_info;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

pub fn initialize() {
    log_info!("RNDC client initialized");
    RNDC_CLIENT.get_or_init(RndcClient::new);
}

pub struct RndcClient {
    client: rndc::RndcClient,
}

impl RndcClient {
    fn new() -> Self {
        let server_url = crate::config::get_config::<String>("bind.rndc_server_url");
        let algorithm = crate::config::get_config::<String>("bind.rndc_algorithm");
        let secret_key = crate::config::get_config::<String>("bind.rndc_secret_key");

        RndcClient {
            client: rndc::RndcClient::new(&server_url, &algorithm, &secret_key),
        }
    }

    pub fn command(&self, command: &str) -> Result<rndc::RndcResult, String> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let res = self.client.rndc_command(command)?;

            if !res.result {
                return Err("Failed to execute RNDC command".to_string());
            }

            Ok(res)
        }));

        match result {
            Ok(res) => res,
            Err(_) => Err("Panic occurred while accessing RNDC client".to_string()),
        }
    }
}

pub static RNDC_CLIENT: OnceLock<RndcClient> = OnceLock::new();

pub fn get_rndc_client() -> &'static RndcClient {
    RNDC_CLIENT.get().expect("RNDC client is not initialized")
}
