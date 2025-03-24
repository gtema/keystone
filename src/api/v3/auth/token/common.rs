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

use crate::api::common;
use crate::api::error::{KeystoneApiError, TokenError};
use crate::api::v3::auth::token::types::{ProjectBuilder, Token, TokenBuilder, UserBuilder};
use crate::api::v3::role::types::Role;
use crate::identity::{IdentityApi, types::UserResponse};
use crate::keystone::ServiceState;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
use crate::token::Token as ProviderToken;

impl Token {
    // TODO: Join both methods
    pub async fn from_user_auth(
        state: &ServiceState,
        token: &ProviderToken,
        user: &UserResponse,
        project: Option<&Project>,
        domain: Option<&Domain>,
    ) -> Result<Token, KeystoneApiError> {
        let mut response = TokenBuilder::default();
        response.audit_ids(token.audit_ids().clone());
        response.methods(token.methods().clone());
        response.expires_at(*token.expires_at());

        let user_domain = common::get_domain(state, Some(&user.domain_id), None::<&str>).await?;

        let mut user_response: UserBuilder = UserBuilder::default();
        user_response.id(user.id.clone());
        user_response.name(user.name.clone());
        user_response.password_expires_at(user.password_expires_at);
        user_response.domain(user_domain.clone());
        response.user(user_response.build().map_err(TokenError::from)?);

        match token {
            ProviderToken::Unscoped(_token) => {
                // Nothing to do
            }
            ProviderToken::DomainScope(_token) => {
                response.domain(domain.ok_or(KeystoneApiError::InternalError(
                    "domain scope information missing".to_string(),
                ))?);
            }
            ProviderToken::ProjectScope(token) => {
                let project = project.ok_or(KeystoneApiError::InternalError(
                    "project scope information missing".to_string(),
                ))?;

                let mut project_response = ProjectBuilder::default();
                project_response.id(project.id.clone());
                project_response.name(project.name.clone());
                if project.domain_id == user.domain_id {
                    project_response.domain(user_domain.clone().into());
                } else {
                    let project_domain =
                        common::get_domain(state, Some(&project.domain_id), None::<&str>).await?;
                    project_response.domain(project_domain.clone().into());
                }
                response.project(project_response.build().map_err(TokenError::from)?);

                response.roles(
                    token
                        .roles
                        .clone()
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<Role>>(),
                );
            }
            ProviderToken::ApplicationCredential(_token) => {
                todo!();
            }
        }
        Ok(response.build().map_err(TokenError::from)?)
    }

    pub async fn from_provider_token(
        state: &ServiceState,
        token: &ProviderToken,
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

        let user_domain = common::get_domain(state, Some(&user.domain_id), None::<&str>).await?;

        let mut user_response: UserBuilder = UserBuilder::default();
        user_response.id(user.id.clone());
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
                    let domain =
                        common::get_domain(state, Some(&token.domain_id), None::<&str>).await?;
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
                    let project_domain =
                        common::get_domain(state, Some(&project.domain_id), None::<&str>).await?;
                    project_response.domain(project_domain.clone().into());
                }
                response.project(project_response.build().map_err(TokenError::from)?);

                response.roles(
                    token
                        .roles
                        .clone()
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<Role>>(),
                );
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
    use crate::api::v3::role::types::Role;
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Assignment, AssignmentType, Role as ProviderRole, RoleAssignmentListParameters},
    };
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::UserResponse};
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
                Ok(Some(UserResponse {
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
            &state,
            &ProviderToken::Unscoped(UnscopedToken {
                user_id: "bar".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
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
                Ok(Some(UserResponse {
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
            &state,
            &ProviderToken::DomainScope(DomainScopeToken {
                user_id: "bar".into(),
                domain_id: "domain_id".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        assert_eq!(
            Some("domain_id"),
            api_token.domain.expect("domain scope").id.as_deref()
        );
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
                Ok(Some(UserResponse {
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
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock.expect_list_role_assignments().returning(
            |_, _, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            },
        );
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
            &state,
            &ProviderToken::ProjectScope(ProjectScopeToken {
                user_id: "bar".into(),
                project_id: "project_id".into(),
                roles: vec![ProviderRole {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        let project = api_token.project.expect("project_scope");
        assert_eq!(Some("project_domain_id"), project.domain.id.as_deref());
        assert_eq!("project_id", project.id);
        assert!(api_token.domain.is_none());
        assert_eq!(
            api_token.roles,
            Some(vec![Role {
                id: "rid".into(),
                name: "role_name".into(),
                ..Default::default()
            }])
        );
    }
}
