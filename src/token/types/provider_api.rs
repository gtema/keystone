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
//! Token provider types.

use async_trait::async_trait;
use sea_orm::DatabaseConnection;

use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::provider::Provider;
use crate::token::TokenProviderError;

use super::*;

/// Token Provider interface.
#[async_trait]
pub trait TokenApi: Send + Sync + Clone {
    async fn authenticate_by_token<'a>(
        &self,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticatedInfo, TokenProviderError>;

    /// Validate the token
    async fn validate_token<'a>(
        &self,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError>;

    /// Issue a token for given parameters
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restriction: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError>;

    /// Encode the token into the X-SubjectToken String
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

    /// Populate role assignments in the token that support that information
    async fn populate_role_assignments(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError>;

    /// Populate additional information (project, domain, roles, etc) in the token that support
    /// that information
    async fn expand_token_information(
        &self,
        token: &Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<Token, TokenProviderError>;

    /// Get the token restriction by the ID.
    async fn get_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError>;

    /// Create new token restriction.
    async fn create_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError>;

    /// List token restrictions.
    async fn list_token_restrictions<'a>(
        &self,
        db: &DatabaseConnection,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

    /// Update token restriction by the ID.
    async fn update_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError>;

    /// Delete token restriction by the ID.
    async fn delete_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), TokenProviderError>;
}
