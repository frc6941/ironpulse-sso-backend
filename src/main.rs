mod requests;
mod responses;
mod handlers;
mod tables;
mod query;
mod jwt;
mod errors;

use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use axum::{Router, serve};
use axum::routing::get;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use tracing_subscriber::EnvFilter;
use crate::handlers::oidc::authorize;

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or("postgres://postgres:password@localhost".into());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database.");

    let app = Router::new()
        .route("/authorize", get(authorize))
        .with_state(pool);

    let host = env::var("HOST").unwrap_or("127.0.0.1".into());
    let port = env::var("PORT").unwrap_or("8080".into());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid host or port");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", addr);
    serve(listener, app).await.unwrap();
}
