use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_url: Option<String>,
    scope: Option<String>,
    state: Option<String>
}