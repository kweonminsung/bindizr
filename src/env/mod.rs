use dotenvy::from_filename;
use lazy_static::lazy_static;
use std::env;

pub fn initialize() {
    lazy_static! {
        static ref _ENV_LOADED: () = {
            from_filename("./bindizr.conf").ok();
        };
    }

    lazy_static::initialize(&_ENV_LOADED);

    // Debugging: Print all environment variables
    // for (key, value) in env::vars() {
    //     println!("{}: {}", key, value);
    // }
}

pub fn get_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("Env: {} not set", key))
}
