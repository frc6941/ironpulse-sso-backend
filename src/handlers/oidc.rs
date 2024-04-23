use axum::extract::Query;
use axum::response::IntoResponse;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;

use crate::errors::APIError;
use crate::requests::oidc::AuthorizeParams;

pub async fn authorize(
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    Query(params): Query<AuthorizeParams>
) -> Result<impl IntoResponse, APIError> {
    // let token = authorization.token();
    Ok(())
}

pub async fn token() {

}

pub async fn login(

) {

}
