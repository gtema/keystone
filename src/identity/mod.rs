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

pub mod backends;
pub mod error;
pub mod types;

use crate::config::Config;
use crate::identity::error::IdentityProviderError;
use backends::sql::SqlDriver;
use types::IdentityBackend;
use types::User;

#[derive(Debug)]
pub struct IdentitySrv {
    //config: Config,
    backend_driver: Box<dyn IdentityBackend>,
}

impl IdentitySrv {
    pub fn new(config: &Config) -> Result<Self, IdentityProviderError> {
        let driver: Box<dyn IdentityBackend> = match &config.identity {
            Some(identity_config) => match identity_config.driver.as_str() {
                "sql" => Box::new(SqlDriver {
                    config: config.clone(),
                }),
                _ => {
                    return Err(IdentityProviderError::UnsupportedDriver(
                        identity_config.driver.clone(),
                    ));
                }
            },
            _ => Box::new(SqlDriver {
                config: config.clone(),
            }),
        };
        Ok(Self {
            backend_driver: driver,
        })
    }

    /// List users
    #[tracing::instrument(level = "info", skip(self, db))]
    pub async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &types::UserListParameters,
    ) -> Result<Vec<User>, IdentityProviderError> {
        tracing::debug!("Fetching user list!");
        let result = self.backend_driver.list(db, params).await?;
        tracing::debug!("User fetching complete!");
        Ok(result)
    }

    /// Get single user
    #[tracing::instrument(level = "info", skip(self, db, user_id), fields(user_id = %user_id.as_ref()))]
    pub async fn get_user<S: AsRef<str> + std::fmt::Debug>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<Option<User>, IdentityProviderError> {
        tracing::debug!("Fetching user details!");
        let result = self
            .backend_driver
            .get(db, user_id.as_ref().to_string())
            .await?;
        tracing::debug!("User fetching complete!");
        Ok(result)
    }
}
