#![feature(duration_constructors)]
#![feature(unwrap_infallible)]

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
use axum::routing::{get, post};
use bb8_redis::RedisConnectionManager;
use dotenv::dotenv;
use sqlx::{PgPool, Pool, Postgres};
use sqlx::postgres::PgPoolOptions;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::TraceLayer;
use tracing::{error, info, Span};
use tracing_subscriber::EnvFilter;
use crate::handlers::oidc::{authorize, login, token};
use crate::jwt::JwtHelper;

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or("postgres://postgres:password@localhost".into());
    let postgres_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database.");

    let redis_manager = RedisConnectionManager::new("redis://localhost")
        .unwrap();
    let redis_pool = bb8::Pool::builder()
        .build(redis_manager)
        .await
        .unwrap();

    let jwt_helper = JwtHelper::new();

    let app_state = AppState {
        postgres_pool,
        redis_pool,
        jwt_helper
    };

    let app = Router::new()
        .route("/oauth2/authorize", get(authorize))
        .route("/login", post(login))
        .route("/oauth2/token", post(token))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let host = env::var("HOST").unwrap_or("127.0.0.1".into());
    let port = env::var("PORT").unwrap_or("8080".into());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid host or port");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", addr);
    serve(listener, app).await.unwrap();
}

#[derive(Clone)]
pub struct AppState {
    postgres_pool: Pool<Postgres>,
    redis_pool: bb8::Pool<RedisConnectionManager>,
    jwt_helper: JwtHelper
}
