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
use std::collections::HashMap;

use sea_orm::DatabaseConnection;

use super::super::types::*;
use crate::config::Config;

use crate::identity::IdentityProviderError;

#[derive(Clone, Debug, Default)]
pub struct FakeBackend {
    pub config: Config,
    pub users: HashMap<String, User>,
}

impl FakeBackend {}

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

#[async_trait]
impl IdentityBackend for FakeBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Fetch users from the database
    async fn list_users(
        &self,
        _db: &DatabaseConnection,
        _params: &UserListParameters,
    ) -> Result<Vec<User>, IdentityProviderError> {
        Ok(self.users.values().cloned().collect())
    }

    /// Get single user by ID
    async fn get_user(
        &self,
        _db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Option<User>, IdentityProviderError> {
        Ok(self.users.get(&user_id).cloned())
    }

    /// Create user
    async fn create_user(
        &mut self,
        _db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError> {
        let entry = self.users.insert(user.id.clone(), user.into()).unwrap();

        Ok(entry)
    }

    /// Delete user
    async fn delete_user(
        &mut self,
        _db: &DatabaseConnection,
        user_id: String,
    ) -> Result<(), IdentityProviderError> {
        if self.users.contains_key(&user_id) {
            self.users.remove(&user_id);
        } else {
            return Err(IdentityProviderError::UserNotFound(user_id));
        }
        Ok(())
    }
}
