mod api;
mod database;
mod env;

fn main() {
    // Load environment variables
    env::initialize();

    // Initialize API server
    if let Err(e) = api::initialize() {
        eprintln!("Error starting server: {}", e);
        return;
    }
}
