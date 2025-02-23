// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
#[cfg(test)]
use mockall::mock;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

pub mod backends;
pub mod error;
pub mod password_hashing;
pub(crate) mod types;

use crate::config::Config;
use crate::identity::backends::sql::SqlBackend;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{
    IdentityBackend,
    {Group, GroupCreate, GroupListParameters, User, UserCreate, UserListParameters},
};
use crate::plugin_manager::PluginManager;

#[derive(Clone, Debug)]
pub struct IdentityProvider {
    backend_driver: Box<dyn IdentityBackend>,
}

#[async_trait]
pub trait IdentityApi: Send + Sync + Clone {
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError>;

    async fn get_user(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Option<User>, IdentityProviderError>;

    async fn create_user(
        &self,
        db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError>;

    async fn delete_user(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<(), IdentityProviderError>;

    async fn list_groups(
        &self,
        db: &DatabaseConnection,
        params: &GroupListParameters,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError>;

    async fn get_group(
        &self,
        db: &DatabaseConnection,
        group_id: String,
    ) -> Result<Option<Group>, IdentityProviderError>;

    async fn create_group(
        &self,
        db: &DatabaseConnection,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError>;

    async fn delete_group(
        &self,
        db: &DatabaseConnection,
        group_id: String,
    ) -> Result<(), IdentityProviderError>;
}

#[cfg(test)]
mock! {
    pub IdentityProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, IdentityProviderError>;
    }

    #[async_trait]
    impl IdentityApi for IdentityProvider {
       async fn list_users(
           &self,
           db: &DatabaseConnection,
           params: &UserListParameters,
       ) -> Result<Vec<User>, IdentityProviderError>;

       async fn get_user(
           &self,
           db: &DatabaseConnection,
           user_id: String,
       ) -> Result<Option<User>, IdentityProviderError>;

       async fn create_user(
           &self,
           db: &DatabaseConnection,
           user: UserCreate,
       ) -> Result<User, IdentityProviderError>;

       async fn delete_user(
           &self,
           db: &DatabaseConnection,
           user_id: String,
       ) -> Result<(), IdentityProviderError>;

       async fn list_groups(
           &self,
           db: &DatabaseConnection,
           params: &GroupListParameters,
       ) -> Result<Vec<Group>, IdentityProviderError>;

       async fn get_group(
           &self,
           db: &DatabaseConnection,
           group_id: String,
       ) -> Result<Option<Group>, IdentityProviderError>;

       async fn create_group(
           &self,
           db: &DatabaseConnection,
           group: GroupCreate,
       ) -> Result<Group, IdentityProviderError>;

       async fn delete_group(
           &self,
           db: &DatabaseConnection,
           group_id: String,
       ) -> Result<(), IdentityProviderError>;
    }

    impl Clone for IdentityProvider {
        fn clone(&self) -> Self;
    }

}

impl IdentityProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, IdentityProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_identity_backend(config.identity.driver.clone())
        {
            driver.clone()
        } else {
            match config.identity.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(IdentityProviderError::UnsupportedDriver(
                        config.identity.driver.clone(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl IdentityApi for IdentityProvider {
    /// List users
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError> {
        self.backend_driver.list_users(db, params).await
    }

    /// Get single user
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_user(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Option<User>, IdentityProviderError> {
        self.backend_driver.get_user(db, user_id).await
    }

    /// Create user
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn create_user(
        &self,
        db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError> {
        let mut mod_user = user;
        mod_user.id = Uuid::new_v4().into();
        if mod_user.enabled.is_none() {
            mod_user.enabled = Some(true);
        }
        self.backend_driver.create_user(db, mod_user).await
    }

    /// Delete user
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn delete_user(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_user(db, user_id).await
    }

    /// List groups
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_groups(
        &self,
        db: &DatabaseConnection,
        params: &GroupListParameters,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError> {
        self.backend_driver.list_groups(db, params).await
    }

    /// Get single group
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_group(
        &self,
        db: &DatabaseConnection,
        group_id: String,
    ) -> Result<Option<Group>, IdentityProviderError> {
        self.backend_driver.get_group(db, group_id).await
    }

    /// Create group
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn create_group(
        &self,
        db: &DatabaseConnection,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        let mut res = group;
        res.id = Some(Uuid::new_v4().into());
        self.backend_driver.create_group(db, res).await
    }

    /// Delete group
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn delete_group(
        &self,
        db: &DatabaseConnection,
        group_id: String,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_group(db, group_id).await
    }
}
