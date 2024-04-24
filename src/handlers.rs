use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::Json;
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::{CookieJar, WithRejection};
use redis::AsyncCommands;
use uuid::Uuid;

use crate::AppState;
use crate::errors::APIError;
use crate::errors::APIError::{ClientNotExists, RedisError, Unauthorized};
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
    let token = match cookie_jar.get("ip_sso_token") {
        None => return Ok(Redirect::to("/login")),
        Some(token) => token
    };
    let token_data = match state.jwt_helper.decode::<LocalClaims>(&token.value().to_string()) {
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

    if !conn.exists(format!("{}:{}", params.client_id, token_data.claims.uid))
        .await.map_err(|e| RedisError(e))? {
        let code = Uuid::new_v4();
        conn.set_ex(
            format!("{}:{}", params.client_id, token_data.claims.uid),
            code.to_string(),
            Duration::from_mins(5).as_secs()
        ).await.map_err(|e| RedisError(e))?;
    }

    let code: String = conn.get(format!("{}:{}", params.client_id, token_data.claims.uid))
        .await.unwrap();

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
    cookie_jar: CookieJar,
    WithRejection(Query(params), _): WithRejection<Query<TokenParams>, APIError>
) -> Result<impl IntoResponse, APIError> {
    if let None = get_client(&state.postgres_pool, &params.client_id, &params.client_secret).await {
        return Err(ClientNotExists)
    }
    let token = match cookie_jar.get("ip_sso_token") {
        None => return Ok(Redirect::to("/login").into_response()),
        Some(token) => token
    };
    let token_data = match state.jwt_helper.decode::<LocalClaims>(&token.value().to_string()) {
        Ok(data) => data,
        Err(_) => return Ok(Redirect::to("/login").into_response())
    };
    let mut conn = state.redis_pool
        .get()
        .await
        .unwrap();
    if !conn.exists(format!("{}:{}", params.client_id, token_data.claims.uid))
        .await.map_err(|e| RedisError(e))? {
        return Err(Unauthorized)
    }
    let code: String = conn.get(format!("{}:{}", params.client_id, token_data.claims.uid))
        .await.unwrap();
    if code != params.code {
        return Err(Unauthorized)
    }
    let access_claims = OAuthClaims {
        sub: token_data.claims.uid.to_string(),
        exp: SystemTime::now().add(Duration::from_mins(5)).duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
        client_id: params.client_id.clone(),
    };
    let access_token = state.jwt_helper.encode(&access_claims);

    let refresh_claims = OAuthClaims {
        sub: token_data.claims.uid,
        exp: SystemTime::now().add(Duration::from_days(5)).duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
        client_id: params.client_id,
    };
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
    let user = match verify_password(&state.postgres_pool, payload.username, payload.password).await {
        None => return Err(Unauthorized),
        Some(user) => user
    };
    let claims = LocalClaims {
        sub: user.username,
        exp: SystemTime::now().add(Duration::from_mins(10)).duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
        uid: user.uid.to_string(),
    };

    Ok(
        LoginResponse {
            token: state.jwt_helper.encode(&claims),
        }.into_response()
    )
}
