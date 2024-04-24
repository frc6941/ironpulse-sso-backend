use sqlx::{Pool, Postgres};
use crate::tables::client::Client;

pub async fn is_client_exists(pool: &Pool<Postgres>, client_id: &String) -> bool {
    sqlx::query_as::<_, Client>("select * from client_table where client_id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await
        .unwrap()
        .is_some()
}