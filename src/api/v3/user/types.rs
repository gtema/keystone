use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::identity::types;

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct User {
    /// User ID
    pub id: String,
    pub domain_id: String,
    pub name: Option<String>,
}

impl From<types::User> for User {
    fn from(value: types::User) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct Users {
    /// Collection of user objects
    pub users: Vec<User>,
}

impl From<Vec<types::User>> for Users {
    fn from(value: Vec<types::User>) -> Self {
        let objects: Vec<User> = value.into_iter().map(User::from).collect();
        Self { users: objects }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct UserListParameters {
    pub limit: i32,
}
