use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum APIError {
    #[error("SQL error: {0}")]
    SQL(#[from] sqlx::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError)
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}
