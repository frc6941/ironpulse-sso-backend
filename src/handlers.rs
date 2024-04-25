use std::time::Duration;

use axum::extract::{Query, State};
use axum::Json;
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::{CookieJar, WithRejection};
use redis::AsyncCommands;
use uuid::Uuid;

use crate::AppState;
use crate::errors::APIError;
use crate::errors::APIError::{ClientNotExists, NotSupportAuthenticationMethod, RedisError, Unauthorized};
use crate::jwt::{LocalClaims, OAuthClaims};
use crate::query::client::{get_client, is_client_exists};
use crate::query::user::verify_password;
use crate::requests::{AuthorizeParams, LoginRequest, TokenParams};
use crate::responses::{LoginResponse, TokenResponse};

pub async fn authorize(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    WithRejection(Query(params), _): WithRejection<Query<AuthorizeParams>, APIError>
) -> Result<impl IntoResponse, APIError> {
    if params.response_type != "code" {
        return Err(NotSupportAuthenticationMethod)
    }
    let token = match cookie_jar.get("ip_sso_token") {
        None => return Ok(Redirect::to("/login")),
        Some(token) => token.value().to_string()
    };
    let token_data = match state.jwt_helper.decode::<LocalClaims>(&token) {
        Ok(data) => data,
        Err(_) => return Ok(Redirect::to("/login"))
    };
    if !is_client_exists(&state.postgres_pool, &params.client_id).await {
        return Err(ClientNotExists)
    }
    let mut conn = state.redis_pool
        .get()
        .await
        .unwrap();

    let code = Uuid::new_v4();
    conn.set_ex(
        code.to_string(),
        format!("{}:{}", params.client_id, token_data.claims.sub),
        Duration::from_mins(5).as_secs()
    ).await.map_err(RedisError)?;

    let state_param = match params.state {
        None => "",
        Some(state) => &*format!("&state={}", state)
    };

    Ok(
        Redirect::to(
            format!(
                "{}?code={}{}",
                params.redirect_uri,
                code,
                state_param
            ).as_str()
        )
    )
}

pub async fn token(
    State(state): State<AppState>,
    WithRejection(Query(params), _): WithRejection<Query<TokenParams>, APIError>
) -> Result<impl IntoResponse, APIError> {
    if get_client(
        &state.postgres_pool,
        &params.client_id,
        &params.client_secret
    ).await.is_none() {
        return Err(ClientNotExists)
    }
    let mut conn = state.redis_pool
        .get()
        .await
        .unwrap();
    if !conn.exists(params.code.clone()).await.map_err(RedisError)? {
        return Err(Unauthorized)
    }
    let client_id_uid: String = conn.get(params.code).await.map_err(RedisError)?;
    let mut client_id_uid = client_id_uid.split(':')
        .map(|x| x.to_string());
    let client_id = client_id_uid.next().unwrap();
    let uid = client_id_uid.next().unwrap();
    let access_claims = OAuthClaims::new(uid.clone(), client_id.clone());
    let access_token = state.jwt_helper.encode(&access_claims);

    let refresh_claims = OAuthClaims::new(uid, client_id);
    let refresh_token = state.jwt_helper.encode(&refresh_claims);

    Ok(
        TokenResponse {
            access_token,
            refresh_token,
        }.into_response()
    )
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>
) -> Result<impl IntoResponse, APIError> {
    let uid = match verify_password(
        &state.postgres_pool,
        payload.username,
        payload.password
    ).await {
        None => return Err(Unauthorized),
        Some(user) => user.uid.to_string()
    };
    let claims = LocalClaims::new(uid);

    Ok(
        LoginResponse {
            token: state.jwt_helper.encode(&claims),
        }.into_response()
    )
}
