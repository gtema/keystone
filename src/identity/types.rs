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
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::config::Config;
use crate::identity::IdentityProviderError;

pub use crate::identity::types::group::{Group, GroupCreate, GroupListParameters};
pub use crate::identity::types::user::*;
//pub use crate::identity::types::user::{
//    DomainBuilder, DomainBuilderError, UserCreate, UserListParameters, UserOptions,
//    UserPasswordAuthRequest, UserPasswordAuthRequestBuilder, UserResponse, UserResponseBuilder,
//    UserResponseBuilderError,
//};

#[async_trait]
pub trait IdentityBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// Authenticate a user by a password
    async fn authenticate_by_password(
        &self,
        db: &DatabaseConnection,
        auth: UserPasswordAuthRequest,
    ) -> Result<UserResponse, IdentityProviderError>;

    /// List Users
    async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError>;

    /// Get single user by ID
    async fn get_user<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    /// Find federated user by IDP and Unique ID
    async fn find_federated_user<'a>(
        &self,
        db: &DatabaseConnection,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    /// Create user
    async fn create_user(
        &self,
        db: &DatabaseConnection,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError>;

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

    /// List groups a user is member of
    async fn list_groups_for_user<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// List user passkeys
    async fn list_user_passkeys<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Vec<Passkey>, IdentityProviderError>;

    /// Create passkey
    async fn create_user_passkey<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
        passkey: Passkey,
    ) -> Result<(), IdentityProviderError>;

    /// Save passkey registration state
    async fn create_user_passkey_registration_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
        state: PasskeyRegistration,
    ) -> Result<(), IdentityProviderError>;

    /// Save passkey auth state
    async fn create_user_passkey_authentication_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
        state: PasskeyAuthentication,
    ) -> Result<(), IdentityProviderError>;

    /// Get passkey registration state
    async fn get_user_passkey_registration_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, IdentityProviderError>;

    /// Get passkey authentication state
    async fn get_user_passkey_authentication_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, IdentityProviderError>;

    /// Delete passkey registration state of a user
    async fn delete_user_passkey_registration_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Delete passkey authentication state of a user
    async fn delete_user_passkey_authentication_state<'a>(
        &self,
        db: &DatabaseConnection,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;
}

dyn_clone::clone_trait_object!(IdentityBackend);
