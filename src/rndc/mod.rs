use lazy_static::lazy_static;
use rndc::RndcClient;

lazy_static! {
    pub static ref RNDC_CLIENT: RndcClient = {
        let server_url = crate::config::get_config("bind.rndc_server_url");
        let algorithm = crate::config::get_config("bind.rndc_algorithm");
        let secret_key = crate::config::get_config("bind.rndc_secret_key");

        RndcClient::new(&server_url, &algorithm, &secret_key)
    };
}
