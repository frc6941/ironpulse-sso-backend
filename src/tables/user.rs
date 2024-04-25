use uuid::Uuid;

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub uid: Uuid,
    pub username: String,
    pub email: String,
    pub phone: String,
}
