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
use sea_orm::DatabaseConnection;
#[cfg(test)]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub mod backends;
pub mod error;
pub mod password_hashing;
pub(crate) mod types;

use crate::config::Config;
use crate::identity::backends::sql::SqlBackend;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::IdentityBackend;
use crate::identity::types::{User, UserCreate};
use crate::plugin_manager::PluginManager;

#[derive(Clone, Debug)]
pub struct IdentitySrv {
    backend_driver: Box<dyn IdentityBackend>,
}

#[async_trait]
pub trait IdentityApi: Send + Sync + Clone {
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &types::UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError>;

    async fn get_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<Option<User>, IdentityProviderError>;

    async fn create_user(
        &self,
        db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError>;

    async fn delete_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<(), IdentityProviderError>;
}

impl IdentitySrv {
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
impl IdentityApi for IdentitySrv {
    /// List users
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &types::UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError> {
        let result = self.backend_driver.list_users(db, params).await?;
        Ok(result)
    }

    /// Get single user
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<Option<User>, IdentityProviderError> {
        let result = self
            .backend_driver
            .get_user(db, user_id.as_ref().to_string())
            .await?;
        Ok(result)
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
        let new_user = self.backend_driver.create_user(db, mod_user).await?;
        Ok(new_user)
    }

    /// Delete user
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn delete_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .delete_user(db, user_id.as_ref().to_string())
            .await
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct FakeIdentityProvider {
    map: Arc<Mutex<HashMap<String, User>>>,
}

#[cfg(test)]
impl From<UserCreate> for User {
    fn from(value: UserCreate) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain_id: value.domain_id,
            ..Default::default()
        }
    }
}

#[cfg(test)]
#[async_trait]
impl IdentityApi for FakeIdentityProvider {
    /// List users
    async fn list_users(
        &self,
        _db: &DatabaseConnection,
        _params: &types::UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError> {
        let result: Vec<User> = self.map.lock().unwrap().values().cloned().collect();
        Ok(result)
    }

    /// Get single user
    async fn get_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        _db: &DatabaseConnection,
        user_id: S,
    ) -> Result<Option<User>, IdentityProviderError> {
        let result = self.map.lock().unwrap().get(user_id.as_ref()).cloned();
        Ok(result)
    }

    /// Create user
    async fn create_user(
        &self,
        _db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError> {
        let mut mod_user = user;
        mod_user.id = Uuid::new_v4().into();
        let res = User::from(mod_user);
        self.map.lock().unwrap().insert(res.id.clone(), res.clone());
        Ok(res)
    }

    /// Delete user
    async fn delete_user<S: AsRef<str> + std::fmt::Debug + Send + Sync>(
        &self,
        _db: &DatabaseConnection,
        _user_id: S,
    ) -> Result<(), IdentityProviderError> {
        Ok(())
    }
}
