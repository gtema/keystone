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
use chrono::{Local, TimeDelta};
#[cfg(test)]
use mockall::mock;
use sea_orm::DatabaseConnection;

pub mod application_credential;
pub mod domain_scoped;
pub mod error;
pub mod fernet;
pub mod fernet_utils;
pub mod project_scoped;
pub mod types;
pub mod unscoped;

use crate::assignment::{
    AssignmentApi,
    error::AssignmentProviderError,
    types::{Role, RoleAssignmentListParametersBuilder},
};
use crate::config::{Config, TokenProvider as TokenProviderType};
use crate::provider::Provider;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
pub use error::TokenProviderError;
use types::TokenBackend;

pub use application_credential::ApplicationCredentialToken;
pub use domain_scoped::{DomainScopeToken, DomainScopeTokenBuilder};
pub use project_scoped::{ProjectScopeToken, ProjectScopeTokenBuilder};
pub use types::Token;
pub use unscoped::{UnscopedToken, UnscopedTokenBuilder};

#[derive(Clone, Debug)]
pub struct TokenProvider {
    config: Config,
    backend_driver: Box<dyn TokenBackend>,
}

impl TokenProvider {
    pub fn new(config: &Config) -> Result<Self, TokenProviderError> {
        let mut backend_driver = match config.token.provider {
            TokenProviderType::Fernet => fernet::FernetTokenProvider::default(),
        };
        backend_driver.set_config(config.clone());
        Ok(Self {
            config: config.clone(),
            backend_driver: Box::new(backend_driver),
        })
    }
}

#[async_trait]
pub trait TokenApi: Send + Sync + Clone {
    /// Validate the token
    async fn validate_token<'a>(
        &self,
        credential: &'a str,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError>;

    /// Issue a token for given parameters
    fn issue_token<U>(
        &self,
        user_id: U,
        methods: Vec<String>,
        audit_ids: Vec<String>,
        project: Option<&Project>,
        domain: Option<&Domain>,
    ) -> Result<Token, TokenProviderError>
    where
        U: AsRef<str>;

    /// Encode the token into the X-SubjectToken String
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

    /// Populate role assignments in the token that support that information
    async fn populate_role_assignments(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError>;

    /// Populate Project information in the token that support that information
    async fn expand_project_information(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError>;

    /// Populate Domain information in the token that support that information
    async fn expand_domain_information(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError>;
}

#[async_trait]
impl TokenApi for TokenProvider {
    /// Validate token
    #[tracing::instrument(level = "info", skip(self, credential))]
    async fn validate_token<'a>(
        &self,
        credential: &'a str,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError> {
        let token = self.backend_driver.decode(credential)?;
        if Local::now().to_utc()
            > token
                .expires_at()
                .checked_add_signed(TimeDelta::seconds(window_seconds.unwrap_or(0)))
                .unwrap_or(*token.expires_at())
        {
            return Err(TokenProviderError::Expired);
        }
        Ok(token)
    }

    fn issue_token<U>(
        &self,
        user_id: U,
        methods: Vec<String>,
        audit_ids: Vec<String>,
        project: Option<&Project>,
        domain: Option<&Domain>,
    ) -> Result<Token, TokenProviderError>
    where
        U: AsRef<str>,
    {
        let token = if let Some(project) = project {
            Token::ProjectScope(
                ProjectScopeTokenBuilder::default()
                    .user_id(user_id.as_ref())
                    .methods(methods.into_iter())
                    .audit_ids(audit_ids.into_iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .project_id(project.id.clone())
                    .project(project.clone())
                    .build()?,
            )
        } else if let Some(domain) = domain {
            Token::DomainScope(
                DomainScopeTokenBuilder::default()
                    .user_id(user_id.as_ref())
                    .methods(methods.into_iter())
                    .audit_ids(audit_ids.into_iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .domain_id(domain.id.clone())
                    .domain(domain.clone())
                    .build()?,
            )
        } else {
            Token::Unscoped(
                UnscopedTokenBuilder::default()
                    .user_id(user_id.as_ref())
                    .methods(methods.into_iter())
                    .audit_ids(audit_ids.into_iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .build()?,
            )
        };
        Ok(token)
    }

    /// Validate token
    fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError> {
        self.backend_driver.encode(token)
    }

    /// Populate role assignments in the token that support that information
    async fn populate_role_assignments(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError> {
        match token {
            Token::ProjectScope(data) => {
                let token_roles = provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        db,
                        provider,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&data.user_id)
                            .project_id(&data.project_id)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await?;
                data.roles = token_roles
                    .into_iter()
                    .map(|x| Role {
                        id: x.role_id.clone(),
                        name: x.role_name.clone().unwrap_or_default(),
                        ..Default::default()
                    })
                    .collect::<Vec<Role>>();
            }
            Token::DomainScope(data) => {
                let token_roles = provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        db,
                        provider,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&data.user_id)
                            .domain_id(&data.domain_id)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await?;
                data.roles = token_roles
                    .into_iter()
                    .map(|x| Role {
                        id: x.role_id.clone(),
                        name: x.role_name.clone().unwrap_or_default(),
                        ..Default::default()
                    })
                    .collect::<Vec<Role>>();
            }
            Token::ApplicationCredential(data) => {
                let token_roles = provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        db,
                        provider,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&data.user_id)
                            .project_id(&data.project_id)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await?;
                data.roles = token_roles
                    .into_iter()
                    .map(|x| Role {
                        id: x.role_id.clone(),
                        name: x.role_name.clone().unwrap_or_default(),
                        ..Default::default()
                    })
                    .collect::<Vec<Role>>();
            }
            _ => {}
        }

        Ok(())
    }

    async fn expand_project_information(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError> {
        match token {
            Token::ProjectScope(data) => {
                if data.project.is_none() {
                    let project = provider
                        .get_resource_provider()
                        .get_project(db, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::ApplicationCredential(data) => {
                if data.project.is_none() {
                    let project = provider
                        .get_resource_provider()
                        .get_project(db, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            _ => {}
        };
        Ok(())
    }

    async fn expand_domain_information(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError> {
        if let Token::DomainScope(data) = token {
            if data.domain.is_none() {
                let domain = provider
                    .get_resource_provider()
                    .get_domain(db, &data.domain_id)
                    .await?;

                data.domain = domain;
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mock! {
    pub TokenProvider {
        pub fn new(cfg: &Config) -> Result<Self, TokenProviderError>;
    }

    #[async_trait]
    impl TokenApi for TokenProvider {
        async fn validate_token<'a>(
            &self,
            credential: &'a str,
            window_seconds: Option<i64>,
        ) -> Result<Token, TokenProviderError>;

        #[mockall::concretize]
        fn issue_token<U>(
            &self,
            user_id: U,
            methods: Vec<String>,
            audit_ids: Vec<String>,
            project: Option<&Project>,
            domain: Option<&Domain>,
        ) -> Result<Token, TokenProviderError>
        where
            U: AsRef<str>;

        fn encode_token(&self, token: &Token) -> Result<String, TokenProviderError>;

        async fn populate_role_assignments(
            &self,
            token: &mut Token,
            db: &DatabaseConnection,
            provider: &Provider,
        ) -> Result<(), TokenProviderError>;

        async fn expand_project_information(
            &self,
            token: &mut Token,
            db: &DatabaseConnection,
            provider: &Provider,
        ) -> Result<(), TokenProviderError>;

        async fn expand_domain_information(
            &self,
            token: &mut Token,
            db: &DatabaseConnection,
            provider: &Provider,
        ) -> Result<(), TokenProviderError>;

    }

    impl Clone for TokenProvider {
        fn clone(&self) -> Self;
    }

}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;

    use super::*;
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Assignment, AssignmentType, Role, RoleAssignmentListParameters},
    };
    use crate::config::Config;
    use crate::identity::MockIdentityProvider;

    use crate::provider::ProviderBuilder;
    use crate::resource::MockResourceProvider;
    use crate::token::{
        DomainScopeToken, MockTokenProvider, ProjectScopeToken, Token, UnscopedToken,
    };

    #[tokio::test]
    async fn test_populate_role_assignments() {
        let config = Config::default();
        let token_provider = TokenProvider::new(&config).unwrap();
        let db = DatabaseConnection::Disconnected;
        let identity_mock = MockIdentityProvider::default();
        let resource_mock = MockResourceProvider::default();
        let token_mock = MockTokenProvider::default();
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, _, q: &RoleAssignmentListParameters| {
                q.project_id == Some("project_id".to_string())
            })
            .returning(|_, _, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, _, q: &RoleAssignmentListParameters| {
                q.domain_id == Some("domain_id".to_string())
            })
            .returning(|_, _, q: &RoleAssignmentListParameters| {
                Ok(vec![Assignment {
                    role_id: "rid".into(),
                    role_name: Some("role_name".into()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.domain_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }])
            });
        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let mut ptoken = Token::ProjectScope(ProjectScopeToken {
            user_id: "bar".into(),
            project_id: "project_id".into(),
            ..Default::default()
        });
        token_provider
            .populate_role_assignments(&mut ptoken, &db, &provider)
            .await
            .unwrap();

        if let Token::ProjectScope(data) = ptoken {
            assert_eq!(
                data.roles,
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }]
            );
        } else {
            panic!("Not project scope");
        }

        let mut dtoken = Token::DomainScope(DomainScopeToken {
            user_id: "bar".into(),
            domain_id: "domain_id".into(),
            ..Default::default()
        });
        token_provider
            .populate_role_assignments(&mut dtoken, &db, &provider)
            .await
            .unwrap();

        if let Token::DomainScope(data) = dtoken {
            assert_eq!(
                data.roles,
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }]
            );
        } else {
            panic!("Not domain scope");
        }

        let mut utoken = Token::Unscoped(UnscopedToken {
            user_id: "bar".into(),
            ..Default::default()
        });
        assert!(
            token_provider
                .populate_role_assignments(&mut utoken, &db, &provider)
                .await
                .is_ok()
        );
    }
}
