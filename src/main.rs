mod api;
mod database;
mod env;

fn main() {
    // Load environment variables
    env::initialize();

    // Initialize API server
    api::initialize();
}
