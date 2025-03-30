mod api;
mod database;
mod env;

fn main() {
    // Load environment variables
    env::initialize();

    // Initialize database connection
    if let Err(e) = database::initialize() {
        eprintln!("Error initializing database: {}", e);
        return;
    }

    // Initialize API server
    if let Err(e) = api::initialize() {
        eprintln!("Error starting server: {}", e);
        return;
    }
}
