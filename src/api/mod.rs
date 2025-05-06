mod controller;
mod service;
mod utils;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::database::DatabasePool;
use crate::env::get_env;
use controller::ApiController;
use service::ApiService;

pub async fn initialize() {
    let app_port = get_env("API_PORT");

    let addr = SocketAddr::from(([127, 0, 0, 1], app_port.parse::<u16>().unwrap()));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("Listening on http://{}", addr);

    // Create instance for dependency injection
    let database_url = get_env("DATABASE_URL");
    let database_pool: Arc<DatabasePool> = Arc::new(DatabasePool::new(&database_url));

    let service = Arc::new(ApiService::new(database_pool.as_ref().clone()));

    let controller: Arc<Mutex<ApiController>> =
        Arc::new(Mutex::new(ApiController::new(service.as_ref().clone())));

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let controller = controller.clone(); // Clone the shared controller

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let controller = controller.clone();
                        async move {
                            let mut controller = controller.lock().await;
                            controller.route(req)
                        }
                    }),
                )
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
