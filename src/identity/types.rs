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

pub mod group;
pub mod user;

use async_trait::async_trait;
use dyn_clone::DynClone;
use sea_orm::DatabaseConnection;

use crate::config::Config;
use crate::identity::IdentityProviderError;

pub use crate::identity::types::group::{Group, GroupCreate, GroupListParameters};
pub use crate::identity::types::user::{
    User, UserBuilder, UserBuilderError, UserCreate, UserListParameters, UserOptions,
};

#[async_trait]
pub trait IdentityBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List Users
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<Vec<User>, IdentityProviderError>;

    /// Get single user by ID
    async fn get_user<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Option<User>, IdentityProviderError>;

    /// Create user
    async fn create_user(
        &self,
        db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<User, IdentityProviderError>;

    /// Delete user
    async fn delete_user<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// List groups
    async fn list_groups(
        &self,
        db: &DatabaseConnection,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// Get single group by ID
    async fn get_group<'a>(
        &self,
        db: &DatabaseConnection,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError>;

    /// Create group
    async fn create_group(
        &self,
        db: &DatabaseConnection,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError>;

    /// Delete group by ID
    async fn delete_group<'a>(
        &self,
        db: &DatabaseConnection,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;
}

dyn_clone::clone_trait_object!(IdentityBackend);
