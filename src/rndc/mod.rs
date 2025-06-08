use lazy_static::lazy_static;
use std::panic::{catch_unwind, AssertUnwindSafe};

lazy_static! {
    pub(crate) static ref _RNDC_CLIENT: rndc::RndcClient = {
        let server_url = crate::config::get_config::<String>("bind.rndc_server_url");
        let algorithm = crate::config::get_config::<String>("bind.rndc_algorithm");
        let secret_key = crate::config::get_config::<String>("bind.rndc_secret_key");

        rndc::RndcClient::new(&server_url, &algorithm, &secret_key)
    };
}

pub(crate) struct RndcClient;

impl RndcClient {
    pub(crate) fn command(command: &str) -> Result<rndc::RndcResult, String> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let rndc_client = &_RNDC_CLIENT;
            let res = rndc_client.rndc_command(command)?;

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
