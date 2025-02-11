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

use sea_orm::DatabaseConnection;
use uuid::Uuid;

mod backends;
pub mod error;
mod password_hashing;
pub(crate) mod types;

use crate::config::Config;
use crate::identity::backends::sql::SqlBackend;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::IdentityBackend;
use crate::identity::types::{User, UserCreate};

#[derive(Debug)]
pub struct IdentitySrv {
    config: Config,
    backend_driver: Box<dyn IdentityBackend>,
}

impl IdentitySrv {
    pub fn new(config: &Config) -> Result<Self, IdentityProviderError> {
        let driver: Box<dyn IdentityBackend> = match config.identity.driver.as_str() {
            "sql" => Box::new(SqlBackend {
                config: config.clone(),
            }),
            _ => {
                return Err(IdentityProviderError::UnsupportedDriver(
                    config.identity.driver.clone(),
                ));
            }
        };
        Ok(Self {
            config: config.clone(),
            backend_driver: driver,
        })
    }

    /// List users
    #[tracing::instrument(level = "info", skip(self, db))]
    pub async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &types::UserListParameters,
    ) -> Result<impl IntoIterator<Item = User>, IdentityProviderError> {
        let result = self.backend_driver.list_users(db, params).await?;
        Ok(result)
    }

    /// Get single user
    #[tracing::instrument(level = "info", skip(self, db))]
    pub async fn get_user<S: AsRef<str> + std::fmt::Debug>(
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
    pub async fn create_user(
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
    pub async fn delete_user<S: AsRef<str> + std::fmt::Debug>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .delete_user(db, user_id.as_ref().to_string())
            .await
    }
}
