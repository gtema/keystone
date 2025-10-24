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
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Local, TimeDelta};
#[cfg(test)]
use mockall::mock;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

pub mod application_credential;
pub mod domain_scoped;
pub mod error;
pub mod federation_domain_scoped;
pub mod federation_project_scoped;
pub mod federation_unscoped;
pub mod fernet;
pub mod fernet_utils;
pub mod project_scoped;
pub mod restricted;
mod token_restriction;
pub mod types;
pub mod unscoped;

use crate::assignment::{
    AssignmentApi,
    error::AssignmentProviderError,
    types::{Role, RoleAssignmentListParametersBuilder},
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::config::{Config, TokenProvider as TokenProviderType};
use crate::identity::IdentityApi;
use crate::provider::Provider;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
pub use error::TokenProviderError;
use types::TokenBackend;

pub use application_credential::ApplicationCredentialPayload;
pub use domain_scoped::{DomainScopePayload, DomainScopePayloadBuilder};
pub use federation_domain_scoped::{
    FederationDomainScopePayload, FederationDomainScopePayloadBuilder,
};
pub use federation_project_scoped::{
    FederationProjectScopePayload, FederationProjectScopePayloadBuilder,
};
pub use federation_unscoped::{FederationUnscopedPayload, FederationUnscopedPayloadBuilder};
pub use project_scoped::{ProjectScopePayload, ProjectScopePayloadBuilder};
pub use restricted::{RestrictedPayload, RestrictedPayloadBuilder};
pub use types::{
    Token, TokenRestriction, TokenRestrictionCreate, TokenRestrictionListParameters,
    TokenRestrictionUpdate,
};
pub use unscoped::{UnscopedPayload, UnscopedPayloadBuilder};

#[derive(Clone, Debug)]
pub struct TokenProvider {
    config: Config,
    backend_driver: Box<dyn TokenBackend>,
}

impl TokenProvider {
    pub fn new(config: &Config) -> Result<Self, TokenProviderError> {
        let backend_driver = match config.token.provider {
            TokenProviderType::Fernet => fernet::FernetTokenProvider::new(config.clone()),
        };
        Ok(Self {
            config: config.clone(),
            backend_driver: Box::new(backend_driver),
        })
    }

    fn create_unscoped_token(
        &self,
        authentication_info: &AuthenticatedInfo,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::Unscoped(
            UnscopedPayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .build()?,
        ))
    }

    fn create_project_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        project: &Project,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::ProjectScope(
            ProjectScopePayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .project_id(project.id.clone())
                .project(project.clone())
                .build()?,
        ))
    }

    fn create_domain_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        domain: &Domain,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::DomainScope(
            DomainScopePayloadBuilder::default()
                .user_id(authentication_info.user_id.clone())
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .domain_id(domain.id.clone())
                .domain(domain.clone())
                .build()?,
        ))
    }

    fn create_federated_unscoped_token(
        &self,
        authentication_info: &AuthenticatedInfo,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationUnscoped(
                FederationUnscopedPayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(vec![])
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    fn create_federated_project_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        project: &Project,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationProjectScope(
                FederationProjectScopePayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(
                        authentication_info
                            .user_groups
                            .clone()
                            .iter()
                            .map(|grp| grp.id.clone())
                            .collect::<Vec<_>>(),
                    )
                    .project_id(project.id.clone())
                    .project(project.clone())
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    fn create_federated_domain_scope_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        domain: &Domain,
    ) -> Result<Token, TokenProviderError> {
        if let (Some(idp_id), Some(protocol_id)) = (
            authentication_info.idp_id.clone(),
            authentication_info.protocol_id.clone(),
        ) {
            Ok(Token::FederationDomainScope(
                FederationDomainScopePayloadBuilder::default()
                    .user_id(authentication_info.user_id.clone())
                    .user(authentication_info.user.clone())
                    .methods(authentication_info.methods.clone().iter())
                    .audit_ids(authentication_info.audit_ids.clone().iter())
                    .expires_at(
                        Local::now()
                            .to_utc()
                            .checked_add_signed(TimeDelta::seconds(
                                self.config.token.expiration as i64,
                            ))
                            .ok_or(TokenProviderError::ExpiryCalculation)?,
                    )
                    .idp_id(idp_id)
                    .protocol_id(protocol_id)
                    .group_ids(
                        authentication_info
                            .user_groups
                            .clone()
                            .iter()
                            .map(|grp| grp.id.clone())
                            .collect::<Vec<_>>(),
                    )
                    .domain_id(domain.id.clone())
                    .domain(domain.clone())
                    .build()?,
            ))
        } else {
            Err(TokenProviderError::FederatedPayloadMissingData)
        }
    }

    /// Create token with the specified restrictions.
    fn create_restricted_token(
        &self,
        authentication_info: &AuthenticatedInfo,
        authz_info: &AuthzInfo,
        restriction: &TokenRestriction,
    ) -> Result<Token, TokenProviderError> {
        Ok(Token::Restricted(
            RestrictedPayloadBuilder::default()
                .user_id(
                    restriction
                        .user_id
                        .as_ref()
                        .unwrap_or(&authentication_info.user_id.clone()),
                )
                .user(authentication_info.user.clone())
                .methods(authentication_info.methods.clone().iter())
                .audit_ids(authentication_info.audit_ids.clone().iter())
                .expires_at(
                    Local::now()
                        .to_utc()
                        .checked_add_signed(TimeDelta::seconds(self.config.token.expiration as i64))
                        .ok_or(TokenProviderError::ExpiryCalculation)?,
                )
                .token_restriction_id(restriction.id.clone())
                .project_id(
                    restriction
                        .project_id
                        .as_ref()
                        .or(match authz_info {
                            AuthzInfo::Project(project) => Some(&project.id),
                            _ => None,
                        })
                        .ok_or_else(|| TokenProviderError::RestrictedTokenNotProjectScoped)?,
                )
                .allow_renew(restriction.allow_renew)
                .allow_rescope(restriction.allow_rescope)
                .roles(restriction.roles.clone())
                .build()?,
        ))
    }
    async fn expand_user_information(
        &self,
        token: &mut Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<(), TokenProviderError> {
        if token.user().is_none() {
            let user = provider
                .get_identity_provider()
                .get_user(db, token.user_id())
                .await?;
            match token {
                Token::ApplicationCredential(data) => {
                    data.user = user;
                }
                Token::Unscoped(data) => {
                    data.user = user;
                }
                Token::ProjectScope(data) => {
                    data.user = user;
                }
                Token::DomainScope(data) => {
                    data.user = user;
                }
                Token::FederationUnscoped(data) => {
                    data.user = user;
                }
                Token::FederationProjectScope(data) => {
                    data.user = user;
                }
                Token::FederationDomainScope(data) => {
                    data.user = user;
                }
                Token::Restricted(data) => {
                    data.user = user;
                }
            }
        }
        Ok(())
    }
}

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

#[async_trait]
impl TokenApi for TokenProvider {
    /// Authenticate by token
    #[tracing::instrument(level = "info", skip(self, credential))]
    async fn authenticate_by_token<'a>(
        &self,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<AuthenticatedInfo, TokenProviderError> {
        let token = self
            .validate_token(credential, allow_expired, window_seconds)
            .await?;
        tracing::debug!("The token is {:?}", token);
        if let Token::Restricted(restriction) = &token
            && !restriction.allow_renew
        {
            return Err(AuthenticationError::TokenRenewalForbidden)?;
        }
        let mut auth_info_builder = AuthenticatedInfo::builder();
        auth_info_builder.user_id(token.user_id());
        auth_info_builder.methods(token.methods().clone());
        auth_info_builder.audit_ids(token.audit_ids().clone());
        if let Token::Restricted(restriction) = &token {
            auth_info_builder.token_restriction_id(restriction.token_restriction_id.clone());
        }
        Ok(auth_info_builder
            .build()
            .map_err(AuthenticationError::from)?)
    }

    /// Validate token
    #[tracing::instrument(level = "info", skip(self, credential))]
    async fn validate_token<'a>(
        &self,
        credential: &'a str,
        allow_expired: Option<bool>,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError> {
        let token = self.backend_driver.decode(credential)?;
        if Local::now().to_utc()
            > token
                .expires_at()
                .checked_add_signed(TimeDelta::seconds(window_seconds.unwrap_or(0)))
                .unwrap_or_else(|| *token.expires_at())
            && !allow_expired.unwrap_or(false)
        {
            return Err(TokenProviderError::Expired);
        }

        Ok(token)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn issue_token(
        &self,
        authentication_info: AuthenticatedInfo,
        authz_info: AuthzInfo,
        token_restrictions: Option<&TokenRestriction>,
    ) -> Result<Token, TokenProviderError> {
        // This should be executed already, but let's better repeat it as last line of defence.
        // It is also necessary to call this before to stop before we start to resolve authz info.
        authentication_info.validate()?;

        // TODO: Check whether it is allowed to change the scope of the token if AuthenticatedInfo
        // already contains scope it was issued for.
        let mut authentication_info = authentication_info;
        authentication_info.audit_ids.push(
            URL_SAFE
                .encode(Uuid::new_v4().as_bytes())
                .trim_end_matches('=')
                .to_string(),
        );
        if let Some(token_restrictions) = &token_restrictions {
            self.create_restricted_token(&authentication_info, &authz_info, token_restrictions)
        } else if authentication_info.idp_id.is_some() && authentication_info.protocol_id.is_some()
        {
            match &authz_info {
                AuthzInfo::Project(project) => {
                    self.create_federated_project_scope_token(&authentication_info, project)
                }
                AuthzInfo::Domain(domain) => {
                    self.create_federated_domain_scope_token(&authentication_info, domain)
                }
                AuthzInfo::Unscoped => self.create_federated_unscoped_token(&authentication_info),
            }
        } else {
            match &authz_info {
                AuthzInfo::Project(project) => {
                    self.create_project_scope_token(&authentication_info, project)
                }
                AuthzInfo::Domain(domain) => {
                    self.create_domain_scope_token(&authentication_info, domain)
                }
                AuthzInfo::Unscoped => self.create_unscoped_token(&authentication_info),
            }
        }
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
                data.roles = Some(
                    provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            db,
                            provider,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .project_id(&data.project_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::DomainScope(data) => {
                data.roles = Some(
                    provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            db,
                            provider,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .domain_id(&data.domain_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::ApplicationCredential(data) => {
                data.roles = provider
                    .get_assignment_provider()
                    .list_role_assignments(
                        db,
                        provider,
                        &RoleAssignmentListParametersBuilder::default()
                            .user_id(&data.user_id)
                            .project_id(&data.project_id)
                            .include_names(true)
                            .effective(true)
                            .build()
                            .map_err(AssignmentProviderError::from)?,
                    )
                    .await?
                    .into_iter()
                    .map(|x| Role {
                        id: x.role_id.clone(),
                        name: x.role_name.clone().unwrap_or_default(),
                        ..Default::default()
                    })
                    .collect();
                if data.roles.is_empty() {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::FederationProjectScope(data) => {
                data.roles = Some(
                    provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            db,
                            provider,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .project_id(&data.project_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::FederationDomainScope(data) => {
                data.roles = Some(
                    provider
                        .get_assignment_provider()
                        .list_role_assignments(
                            db,
                            provider,
                            &RoleAssignmentListParametersBuilder::default()
                                .user_id(&data.user_id)
                                .domain_id(&data.domain_id)
                                .include_names(true)
                                .effective(true)
                                .build()
                                .map_err(AssignmentProviderError::from)?,
                        )
                        .await?
                        .into_iter()
                        .map(|x| Role {
                            id: x.role_id.clone(),
                            name: x.role_name.clone().unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                );
                if data.roles.as_ref().is_none_or(|roles| roles.is_empty()) {
                    return Err(TokenProviderError::ActorHasNoRolesOnTarget);
                }
            }
            Token::Restricted(data) => {
                if data.roles.is_none() {
                    self.get_token_restriction(db, &data.token_restriction_id, true)
                        .await?
                        .inspect(|restrictions| data.roles = restrictions.roles.clone())
                        .ok_or(TokenProviderError::TokenRestrictionNotFound(
                            data.token_restriction_id.clone(),
                        ))?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn expand_token_information(
        &self,
        token: &Token,
        db: &DatabaseConnection,
        provider: &Provider,
    ) -> Result<Token, TokenProviderError> {
        let mut new_token = token.clone();
        match new_token {
            Token::ProjectScope(ref mut data) => {
                if data.project.is_none() {
                    let project = provider
                        .get_resource_provider()
                        .get_project(db, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::ApplicationCredential(ref mut data) => {
                if data.project.is_none() {
                    let project = provider
                        .get_resource_provider()
                        .get_project(db, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::FederationProjectScope(ref mut data) => {
                if data.project.is_none() {
                    let project = provider
                        .get_resource_provider()
                        .get_project(db, &data.project_id)
                        .await?;

                    data.project = project;
                }
            }
            Token::DomainScope(ref mut data) => {
                if data.domain.is_none() {
                    let domain = provider
                        .get_resource_provider()
                        .get_domain(db, &data.domain_id)
                        .await?;

                    data.domain = domain;
                }
            }
            Token::FederationDomainScope(ref mut data) => {
                if data.domain.is_none() {
                    let domain = provider
                        .get_resource_provider()
                        .get_domain(db, &data.domain_id)
                        .await?;

                    data.domain = domain;
                }
            }
            Token::Restricted(ref mut data) => {
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
        self.expand_user_information(&mut new_token, db, provider)
            .await?;
        self.populate_role_assignments(&mut new_token, db, provider)
            .await?;
        Ok(new_token)
    }

    /// Get the token restriction by the ID.
    async fn get_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        expand_roles: bool,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        token_restriction::get(db, id, expand_roles).await
    }

    /// Create new token restriction.
    async fn create_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        let mut restriction = restriction;
        if restriction.id.is_empty() {
            restriction.id = Uuid::new_v4().simple().to_string();
        }
        token_restriction::create(db, restriction).await
    }

    /// List token restrictions.
    async fn list_token_restrictions<'a>(
        &self,
        db: &DatabaseConnection,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError> {
        token_restriction::list(db, params).await
    }

    /// Update existing token restriction.
    async fn update_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        token_restriction::update(db, id, restriction).await
    }

    /// Delete token restriction by the ID.
    async fn delete_token_restriction<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), TokenProviderError> {
        token_restriction::delete(db, id).await
    }
}

#[cfg(test)]
mock! {
    pub TokenProvider {
        pub fn new(cfg: &Config) -> Result<Self, TokenProviderError>;
    }

    #[async_trait]
    impl TokenApi for TokenProvider {
        async fn authenticate_by_token<'a>(
            &self,
            credential: &'a str,
            allow_expired: Option<bool>,
            window_seconds: Option<i64>,
        ) -> Result<AuthenticatedInfo, TokenProviderError>;

        async fn validate_token<'a>(
            &self,
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

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use super::*;
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Assignment, AssignmentType, Role, RoleAssignmentListParameters},
    };

    use crate::config::Config;

    use crate::token::{DomainScopePayload, ProjectScopePayload, Token, UnscopedPayload};

    pub(super) fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        // write fernet key used to generate tokens in python
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override(
                "auth.methods",
                "password,token,openid,application_credential",
            )
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();
        config
    }

    #[tokio::test]
    async fn test_populate_role_assignments() {
        let token_provider = TokenProvider::new(&Config::default()).unwrap();
        let db = DatabaseConnection::Disconnected;
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
        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .build()
            .unwrap();

        let mut ptoken = Token::ProjectScope(ProjectScopePayload {
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
                data.roles.unwrap(),
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }]
            );
        } else {
            panic!("Not project scope");
        }

        let mut dtoken = Token::DomainScope(DomainScopePayload {
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
                data.roles.unwrap(),
                vec![Role {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }]
            );
        } else {
            panic!("Not domain scope");
        }

        let mut utoken = Token::Unscoped(UnscopedPayload {
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
