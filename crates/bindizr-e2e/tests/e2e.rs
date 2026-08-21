mod common;

mod api {
    mod dnssec;
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
    mod dnssec;
    mod nsupdate;
}

mod cli {
    mod config;
    mod daemon;
    mod dnssec;
    mod doctor;
    mod record;
    mod token;
    mod tsig_key;
    mod zone;
}
