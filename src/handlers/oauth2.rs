use std::time::Duration;

use axum::extract::{Query, State};
use axum::{Form, Json};
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::{CookieJar, WithRejection};
use redis::AsyncCommands;
use serde::Serialize;
use uuid::Uuid;

use crate::AppState;
use crate::errors::APIError;
use crate::errors::APIError::{ClientNotExists, NotSupportAuthenticationMethod, RedisError, Unauthorized};
use crate::jwt::{LocalClaims, OAuthClaims};
use crate::query::client::{get_client, is_client_exists};
use crate::query::user::verify_password;
use crate::requests::{AuthorizeParams, LoginRequest, TokenRequest};
use crate::responses::{LoginResponse, TokenResponse};

#[derive(Serialize)]
pub struct QueryParams {
    redirect_uri: String
}

pub async fn authorize(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    WithRejection(Query(params), _): WithRejection<Query<AuthorizeParams>, APIError>
) -> Result<impl IntoResponse, APIError> {
    if params.response_type != "code" {
        return Err(NotSupportAuthenticationMethod)
    }
    let token = match cookie_jar.get("ip_sso_token") {
        None => return Ok(Redirect::to(
            format!("http://localhost:3000/?{}", serde_urlencoded::to_string(QueryParams {
                redirect_uri: format!("http://localhost:8080/oauth2/authorize?redirect_uri={}&client_id=1&response_type=code&state={}", params.redirect_uri, params.state.unwrap_or(String::from(""))),
            }).unwrap()).as_str())),
        Some(token) => token.value().to_string()
    };
    let token_data = match state.jwt_helper.decode::<LocalClaims>(&token) {
        Ok(data) => data,
        Err(_) => return Ok(Redirect::to(
            format!("http://localhost:3000/?{}", serde_urlencoded::to_string(QueryParams {
                redirect_uri: format!("http://localhost:8080/oauth2/authorize?redirect_uri={}&client_id=1&response_type=code&state={}", params.redirect_uri, params.state.unwrap_or(String::from(""))),
            }).unwrap()).as_str()))
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
    Form(payload): Form<TokenRequest>
) -> Result<impl IntoResponse, APIError> {
    if get_client(
        &state.postgres_pool,
        &payload.client_id,
        &payload.client_secret
    ).await.is_none() {
        return Err(ClientNotExists)
    }
    let mut conn = state.redis_pool
        .get()
        .await
        .unwrap();
    if !conn.exists(payload.code.clone()).await.map_err(RedisError)? {
        return Err(Unauthorized)
    }
    let client_id_uid: String = conn.get(payload.code).await.map_err(RedisError)?;
    let mut client_id_uid = client_id_uid.split(':')
        .map(|x| x.to_string());
    let client_id = client_id_uid.next().unwrap();
    let uid = client_id_uid.next().unwrap();
    let access_claims = OAuthClaims::new(uid.clone(), client_id.clone(), "http://localhost:8080/".to_string());
    let access_token = state.jwt_helper.encode(&access_claims);

    let refresh_claims = OAuthClaims::new(uid, client_id, "http://localhost:8080/".to_string());
    let refresh_token = state.jwt_helper.encode(&refresh_claims);

    Ok(
        TokenResponse {
            access_token: access_token.clone(),
            refresh_token,
            id_token: access_token,
            expires_in: 43200,
            token_type: "bearer".to_string(),
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

#[derive(Serialize)]
struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
    grant_types_supported: Vec<String>
}

pub async fn discovery() -> impl IntoResponse {
    Json(
        OpenIdConfiguration {
            issuer: "http://localhost:8080/".to_string(),
            authorization_endpoint: "http://localhost:8080/oauth2/authorize".to_string(),
            token_endpoint: "http://host.docker.internal:8080/oauth2/token".to_string(),
            response_types_supported: vec![
                "code".into(),
                "id_token".into()
            ],
            scopes_supported: vec![
                "openid".into(),
            ],
            grant_types_supported: vec![
                "authorization_code".into(),
                "refresh_token".into()
            ],
        }
    )
}
