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
//! Internal mock structures for the [TokenProvider].

use async_trait::async_trait;
use mockall::mock;
use sea_orm::DatabaseConnection;

use super::error::TokenProviderError;
use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::config::Config;
use crate::provider::Provider;

use super::{
    Token, TokenApi, TokenRestriction, TokenRestrictionCreate, TokenRestrictionListParameters,
    TokenRestrictionUpdate,
};

mock! {
    pub TokenProvider {
        pub fn new(cfg: &Config) -> Result<Self, TokenProviderError>;
    }

    #[async_trait]
    impl TokenApi for TokenProvider {
        async fn authenticate_by_token<'a>(
            &self,
            provider: &Provider,
            db: &DatabaseConnection,
            credential: &'a str,
            allow_expired: Option<bool>,
            window_seconds: Option<i64>,
        ) -> Result<AuthenticatedInfo, TokenProviderError>;

        async fn validate_token<'a>(
            &self,
            provider: &Provider,
            db: &DatabaseConnection,
            credential: &'a str,
            allow_expired: Option<bool>,
            window_seconds: Option<i64>,
        ) -> Result<Token, TokenProviderError>;

        #[mockall::concretize]
        fn issue_token(
            &self,
            authentication_info: AuthenticatedInfo,
            authz_info: AuthzInfo,
            token_restriction: Option<&TokenRestriction>
        ) -> Result<Token, TokenProviderError>;

        fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

        async fn populate_role_assignments(
            &self,
            token: &mut Token,
            db: &DatabaseConnection,
            provider: &Provider,
        ) -> Result<(), TokenProviderError>;

        async fn expand_token_information(
            &self,
            token: &Token,
            db: &DatabaseConnection,
            provider: &Provider,
        ) -> Result<Token, TokenProviderError>;

        async fn get_token_restriction<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
            expand_roles: bool,
        ) -> Result<Option<TokenRestriction>, TokenProviderError>;

        async fn list_token_restrictions<'a>(
            &self,
            db: &DatabaseConnection,
            params: &TokenRestrictionListParameters,
        ) -> Result<Vec<TokenRestriction>, TokenProviderError>;

        async fn create_token_restriction<'a>(
            &self,
            db: &DatabaseConnection,
            restriction: TokenRestrictionCreate,
        ) -> Result<TokenRestriction, TokenProviderError>;

        async fn update_token_restriction<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
            restriction: TokenRestrictionUpdate,
        ) -> Result<TokenRestriction, TokenProviderError>;

        async fn delete_token_restriction<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<(), TokenProviderError>;
    }

    impl Clone for TokenProvider {
        fn clone(&self) -> Self;
    }

}
