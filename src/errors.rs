use axum::extract::rejection::QueryRejection;
use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use axum_extra::typed_header::TypedHeaderRejection;
use serde_json::json;
use thiserror::Error;
use crate::errors::APIError::{NotSupportAuthenticationMethod, Unauthorized};

#[derive(Debug, Error)]
pub enum APIError {
    #[error("SQL error: {0}")]
    SQL(#[from] sqlx::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("TypedHeader error: {0}")]
    TypeHeaderRejection(#[from] TypedHeaderRejection),
    #[error("Query error: {0}")]
    QueryRejection(#[from] QueryRejection),
    #[error("Not support authentication method")]
    NotSupportAuthenticationMethod,
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        match self {
            APIError::SQL(e) => (StatusCode::INTERNAL_SERVER_ERROR, error_response(&e.to_string())),
            APIError::Unauthorized => (StatusCode::UNAUTHORIZED, error_response("Unauthorized")),
            APIError::RedisError(e) => (StatusCode::INTERNAL_SERVER_ERROR, error_response(&e.to_string())),
            APIError::TypeHeaderRejection(e) => (StatusCode::BAD_REQUEST, error_response(&e.to_string())),
            APIError::QueryRejection(e) => (StatusCode::BAD_REQUEST, error_response(&e.to_string())),
            APIError::NotSupportAuthenticationMethod => (StatusCode::BAD_REQUEST, error_response(&*NotSupportAuthenticationMethod.to_string()))
        }.into_response()
    }
}

pub fn error_response(message: &str) -> impl IntoResponse {
    Json(json!({ "message": message }))
}
