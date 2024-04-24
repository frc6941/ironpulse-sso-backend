use sha256::digest;
use sqlx::{Pool, Postgres};

use crate::tables::user::User;

pub async fn verify_password(pool: &Pool<Postgres>, username: String, password: String) -> Option<User> {
    sqlx::query_as::<_, User>("select * from user_table where username = $1 and password = $2")
        .bind(username)
        .bind(digest(password))
        .fetch_optional(pool)
        .await
        .unwrap()
}