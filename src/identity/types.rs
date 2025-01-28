use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    pub domain_id: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserListParameters {}

#[async_trait]
pub trait IdentityBackend: Send + Sync {
    async fn list(&self, db: &DatabaseConnection, params: &UserListParameters) -> Vec<User>;
}

//#[async_trait]
//pub trait IdentityUserSrv {
//    async fn list_users(self, params: &types::UserListParameters) -> Vec<types::User>;
//}
