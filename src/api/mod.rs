use crate::env::get_env;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod controller;
mod service;
mod utils;

#[tokio::main]
pub async fn initialize() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], get_env("API_PORT").parse::<u16>()?));
    let listener = TcpListener::bind(addr).await?;

    println!("Listening on http://{}", addr);

    // Pre-initialize the shared ApiController
    let controller = Arc::new(Mutex::new(controller::ApiController::new().await));

    loop {
        let (stream, _) = listener.accept().await?;
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
                            controller.route(req).await
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
