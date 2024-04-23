use thiserror::Error;

#[derive(Debug, Error)]
pub enum APIError {
    #[error("SQL error: {0}")]
    SQL(#[from] sqlx::Error),
    #[error("Unauthorized")]
    Unauthorized
}