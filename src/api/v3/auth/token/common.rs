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

use crate::api::error::{KeystoneApiError, TokenError};
use crate::api::v3::auth::token::types::{ProjectBuilder, Token, TokenBuilder, UserBuilder};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;
use crate::token::Token as ProviderToken;

impl Token {
    pub async fn from_provider_token(
        token: &ProviderToken,
        state: &ServiceState,
    ) -> Result<Token, KeystoneApiError> {
        let mut response = TokenBuilder::default();
        response.audit_ids(token.audit_ids().clone());
        response.methods(token.methods().clone());
        response.expires_at(*token.expires_at());

        let user = state
            .provider
            .get_identity_provider()
            .get_user(&state.db, token.user_id())
            .await
            .map_err(KeystoneApiError::identity)?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: token.user_id().clone(),
            })?;

        let user_domain = state
            .provider
            .get_resource_provider()
            .get_domain(&state.db, &user.domain_id)
            .await
            .map_err(KeystoneApiError::resource)?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: user.domain_id.clone(),
            })?;

        let mut user_response: UserBuilder = UserBuilder::default();
        user_response.id(user.id);
        user_response.name(user.name);
        user_response.password_expires_at(user.password_expires_at);
        user_response.domain(user_domain.clone());
        response.user(user_response.build().map_err(TokenError::from)?);

        match token {
            ProviderToken::Unscoped(_token) => {
                // Nothing to do
            }
            ProviderToken::DomainScope(token) => {
                if token.domain_id == user.domain_id {
                    response.domain(user_domain.clone());
                } else {
                    let domain = state
                        .provider
                        .get_resource_provider()
                        .get_domain(&state.db, &token.domain_id)
                        .await
                        .map_err(KeystoneApiError::resource)?
                        .ok_or_else(|| KeystoneApiError::NotFound {
                            resource: "domain".into(),
                            identifier: token.domain_id.clone(),
                        })?;
                    response.domain(domain.clone());
                }
            }
            ProviderToken::ProjectScope(token) => {
                let project = state
                    .provider
                    .get_resource_provider()
                    .get_project(&state.db, &token.project_id)
                    .await
                    .map_err(KeystoneApiError::resource)?
                    .ok_or_else(|| KeystoneApiError::NotFound {
                        resource: "project".into(),
                        identifier: token.project_id.clone(),
                    })?;

                let mut project_response = ProjectBuilder::default();
                project_response.id(project.id.clone());
                project_response.name(project.name.clone());
                if project.domain_id == user.domain_id {
                    project_response.domain(user_domain.clone().into());
                } else {
                    let project_domain = state
                        .provider
                        .get_resource_provider()
                        .get_domain(&state.db, &project.domain_id)
                        .await
                        .map_err(KeystoneApiError::resource)?
                        .ok_or_else(|| KeystoneApiError::NotFound {
                            resource: "domain".into(),
                            identifier: user.domain_id.clone(),
                        })?;
                    project_response.domain(project_domain.clone().into());
                }
                response.project(project_response.build().map_err(TokenError::from)?);
            }
            ProviderToken::ApplicationCredential(_token) => {
                todo!();
            }
        }
        Ok(response.build().map_err(TokenError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::api::v3::auth::token::types::Token;
    use crate::assignment::MockAssignmentProvider;
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::User};
    use crate::keystone::Service;
    use crate::provider::ProviderBuilder;
    use crate::resource::{
        MockResourceProvider,
        types::{Domain, Project},
    };
    use crate::token::{
        DomainScopeToken, MockTokenProvider, ProjectScopeToken, Token as ProviderToken,
        UnscopedToken,
    };

    #[tokio::test]
    async fn test_from_unscoped() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(User {
                    id: "bar".into(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let token_mock = MockTokenProvider::default();
        let assignment_mock = MockAssignmentProvider::default();
        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(Service::new(config, db, provider).unwrap());

        let api_token = Token::from_provider_token(
            &ProviderToken::Unscoped(UnscopedToken {
                user_id: "bar".into(),
                ..Default::default()
            }),
            &state,
        )
        .await
        .unwrap();
        assert_eq!("bar", api_token.user.id);
        assert_eq!("user_domain_id", api_token.user.domain.id);
        assert!(api_token.project.is_none());
        assert!(api_token.domain.is_none());
    }

    #[tokio::test]
    async fn test_from_domain_scoped() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(User {
                    id: "bar".into(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    ..Default::default()
                }))
            });
        let token_mock = MockTokenProvider::default();
        let assignment_mock = MockAssignmentProvider::default();
        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(Service::new(config, db, provider).unwrap());

        let api_token = Token::from_provider_token(
            &ProviderToken::DomainScope(DomainScopeToken {
                user_id: "bar".into(),
                domain_id: "domain_id".into(),
                ..Default::default()
            }),
            &state,
        )
        .await
        .unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!("user_domain_id", api_token.user.domain.id);
        assert_eq!("domain_id", api_token.domain.expect("domain scope").id);
        assert!(api_token.project.is_none());
    }

    #[tokio::test]
    async fn test_from_project_scoped() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(User {
                    id: "bar".into(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_project()
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let token_mock = MockTokenProvider::default();
        let assignment_mock = MockAssignmentProvider::default();
        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(Service::new(config, db, provider).unwrap());

        let api_token = Token::from_provider_token(
            &ProviderToken::ProjectScope(ProjectScopeToken {
                user_id: "bar".into(),
                project_id: "project_id".into(),
                ..Default::default()
            }),
            &state,
        )
        .await
        .unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!("user_domain_id", api_token.user.domain.id);
        let project = api_token.project.expect("project_scope");
        assert_eq!("project_domain_id", project.domain.id);
        assert_eq!("project_id", project.id);
        assert!(api_token.domain.is_none());
    }
}
