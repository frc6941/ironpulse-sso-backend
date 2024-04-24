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

pub async fn get_client(
    pool: &Pool<Postgres>,
    client_id: &String,
    client_secret: &String
) -> Option<Client> {
    sqlx::query_as::<_, Client>("select * from client_table where client_id = $1 and client_secret = $2")
        .bind(client_id)
        .bind(client_secret)
        .fetch_optional(pool)
        .await
        .unwrap()
}