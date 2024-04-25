#[allow(dead_code)]
#[derive(sqlx::FromRow)]
pub struct Client {
    pub id: i32,
    pub client_id: String,
    pub client_secret: String
}