pub(crate) mod controller;
mod dto;
mod service;

use crate::{config, log_error, log_info};
use controller::ApiController;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub(crate) async fn initialize() {
    let app_port = config::get_config::<u16>("api.port");

    let addr = SocketAddr::from(([127, 0, 0, 1], app_port));
    let listener = TcpListener::bind(addr).await.unwrap();

    log_info!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(ApiController::serve))
                .await
            {
                log_error!("Error serving connection: {:?}", err);
            }
        });
    }
}
