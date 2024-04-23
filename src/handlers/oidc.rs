use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::AppState;
use crate::errors::APIError;
use crate::errors::APIError::RedisError;
use crate::jwt::LocalClaims;
use crate::requests::oidc::AuthorizeParams;
use crate::responses::oidc::AuthorizeResponse;

pub async fn authorize(
    State(state): State<AppState>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    Query(params): Query<AuthorizeParams>
) -> Result<impl IntoResponse, APIError> {
    let token = authorization.token();
    let token_data = state.jwt_helper.decode::<LocalClaims>(&token.to_string())?;
    let code = Uuid::new_v4();
    let mut conn = state.redis_pool
        .get()
        .await
        .unwrap();
    conn.set_ex(
        format!("{}:{}", params.client_id, token_data.claims.uid),
        code.to_string(),
        Duration::from_mins(5).as_secs()
    ).await.map_err(|e| RedisError(e))?;

    Ok(AuthorizeResponse {
        redirect_url: params.redirect_url,
        code: code.to_string(),
        state: params.state,
    }.into_response())
}

pub async fn token() {

}

pub async fn login(

) {

}
