use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeResponse {
    pub redirect_url: String,
    pub code: String,
    pub state: Option<String>,
}