use lazy_static::lazy_static;
use rndc::RndcClient;

lazy_static! {
    pub static ref RNDC_CLIENT: RndcClient = {
        let server_url = crate::env::get_env("RNDC_SERVER_URL");
        let algorithm = crate::env::get_env("RNDC_ALGORITHM");
        let secret_key = crate::env::get_env("RNDC_SECRET_KEY");
        RndcClient::new(&server_url, &algorithm, &secret_key)
    };
}
