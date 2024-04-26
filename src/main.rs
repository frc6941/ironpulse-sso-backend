#![feature(duration_constructors)]
#![feature(unwrap_infallible)]


mod tables;
mod query;
mod jwt;
mod errors;
mod requests;
mod responses;
mod handlers;
mod config;

use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use axum::{Router, serve};
use axum::routing::{get, post};
use bb8_redis::RedisConnectionManager;
use dotenv::dotenv;
use sqlx::{Pool, Postgres};
use sqlx::postgres::PgPoolOptions;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use crate::config::{Config, OAuth2};
use crate::handlers::admin::{get_clients, get_user, get_users, register_client};
use crate::handlers::oauth2::{authorize, discovery, login, token};
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

    let mut config_file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("config.toml")
        .await
        .expect("Failed to open config.toml");
    let mut content = String::new();
    BufReader::new(&mut config_file)
        .read_to_string(&mut content)
        .await
        .expect("Failed to read config.toml");
    let config = match content.is_empty() {
        true => {
            let config = Config {
                host: "127.0.0.1".to_string(),
                port: 8080,
                root_url: "http://localhost:8080".to_string(),
                frontend_endpoint: "http://localhost:3000".to_string(),
                oauth2: OAuth2 {
                    issuer: "IronPulse SSO".to_string(),
                    local_jwt_expire_mins: 3000,
                    access_token_expire_mins: 3000,
                    refresh_token_expire_mins: 30000,
                    authorization_code_expire_mins: 3000,
                },
            };
            BufWriter::new(config_file).write(toml::to_string(&config).unwrap().as_bytes())
                .await.unwrap();
            config
        }
        false => toml::from_str(content.as_str()).unwrap()
    };

    let app_state = AppState {
        postgres_pool,
        redis_pool,
        jwt_helper,
        config,
    };

    let app = Router::new()
        .route("/oauth2/authorize", get(authorize))
        .route("/login", post(login))
        .route("/oauth2/token", post(token))
        .route("/admin/client/:name", post(register_client))
        .route("/admin/clients", get(get_clients))
        .route("/admin/users", get(get_users))
        .route("/admin/user/:uid", get(get_user))
        .route("/.well-known/openid-configuration", get(discovery))
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
    jwt_helper: JwtHelper,
    config: Config
}
