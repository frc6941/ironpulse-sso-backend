mod requests;
mod responses;
mod handlers;
mod tables;
mod query;

use std::env;
use std::net::SocketAddr;
use axum::{Router, serve};
use axum::routing::get;
use dotenv::dotenv;
use tracing::info;
use tracing_subscriber::EnvFilter;
use crate::handlers::login::login;

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/login", get(login));

    let host = env::var("HOST").unwrap_or("127.0.0.1".into());
    let port = env::var("PORT").unwrap_or("8080".into());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid host or port");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", addr);
    serve(listener, app).await.unwrap();
}
