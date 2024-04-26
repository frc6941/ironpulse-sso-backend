use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub root_url: String,
    pub frontend_endpoint: String,
    pub oauth2: OAuth2
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OAuth2 {
    pub issuer: String,
    pub local_jwt_expire_mins: u64,
    pub access_token_expire_mins: u64,
    pub refresh_token_expire_mins: u64,
    pub authorization_code_expire_mins: u64
}
