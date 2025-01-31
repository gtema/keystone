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
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity::IdentityProviderError;

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct User {
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub enabled: bool,
    #[builder(setter(into, strip_option), default)]
    pub extra: Option<Value>,
    #[builder(setter(into, strip_option), default)]
    pub password_expires_at: Option<DateTime<Utc>>,
    #[builder(setter(into), default)]
    pub options: UserOptions,
}

impl UserBuilder {
    pub fn get_options(&self) -> Option<&UserOptions> {
        self.options.as_ref()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct UserOptions {
    pub ignore_change_password_upon_first_use: Option<bool>,
    pub ignore_password_expiry: Option<bool>,
    pub ignore_lockout_failure_attempts: Option<bool>,
    pub lock_password: Option<bool>,
    pub ignore_user_inactivity: Option<bool>,
    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,
    pub multi_factor_auth_enabled: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserListParameters {
    /// Filter users by the domain
    pub domain_id: Option<String>,
    /// Filter users by the name attribute
    pub name: Option<String>,
}

#[async_trait]
pub trait IdentityBackend: Send + Sync + std::fmt::Debug {
    /// List Users
    async fn list(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<Vec<User>, IdentityProviderError>;

    /// Get single user
    async fn get(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Option<User>, IdentityProviderError>;
}
