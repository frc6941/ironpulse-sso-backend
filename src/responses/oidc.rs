use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeResponse {
    pub redirect_url: String,
    pub code: String,
    pub state: Option<String>,
}

impl IntoResponse for AuthorizeResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub token: String
}

impl IntoResponse for LoginResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
