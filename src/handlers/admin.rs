use axum::extract::{Path, State};
use axum::response::IntoResponse;
use uuid::Uuid;
use crate::AppState;
use crate::errors::APIError;

pub async fn register_client(
    State(state): State<AppState>,
    Path(name): Path<String>
) -> Result<impl IntoResponse, APIError> {
    Ok(())
}

pub async fn get_clients(
    State(state): State<AppState>
) -> Result<impl IntoResponse, APIError> {
    Ok(())
}

pub async fn get_users(
    State(state): State<AppState>
) -> Result<impl IntoResponse, APIError> {
    Ok(())
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(uid): Path<Uuid>
) -> Result<impl IntoResponse, APIError> {
    Ok(())
}
