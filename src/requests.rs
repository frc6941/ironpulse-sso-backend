use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenParams {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String
}
