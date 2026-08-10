mod common;

mod api {
    mod external_dns;
    mod health;
    mod metrics;
    mod notify;
    mod openapi;
    mod record;
    mod token_policy;
    mod tsig_key;
    mod zone;
}

mod dns {
    mod nsupdate;
}

mod cli {
    mod config;
    mod daemon;
    mod doctor;
    mod record;
    mod tsig_key;
    mod zone;
}
