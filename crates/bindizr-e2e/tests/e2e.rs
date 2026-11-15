mod common;

mod api {
    mod common;
    mod dnssec;
    mod dnssec_policy;
    mod external_dns;
    mod health;
    mod logs;
    mod metrics;
    mod notify;
    mod openapi;
    mod record;
    mod role;
    mod secondary;
    mod token;
    mod tsig_key;
    mod zone;
}

mod cli {
    mod common;
    mod config;
    mod daemon;
    mod dnssec;
    mod doctor;
    mod logs;
    mod notify;
    mod record;
    mod role;
    mod secondary;
    mod token;
    mod tsig_key;
    mod zone;
}

mod nsupdate;
mod xfr;
