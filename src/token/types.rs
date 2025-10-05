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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

use crate::assignment::types::Role;
use crate::config::Config;
use crate::identity::types::UserResponse;
use crate::resource::types::{Domain, Project};
use crate::token::TokenProviderError;
use crate::token::application_credential::ApplicationCredentialPayload;
use crate::token::domain_scoped::DomainScopePayload;
use crate::token::federation_domain_scoped::FederationDomainScopePayload;
use crate::token::federation_project_scoped::FederationProjectScopePayload;
use crate::token::federation_unscoped::FederationUnscopedPayload;
use crate::token::project_scoped::ProjectScopePayload;
use crate::token::restricted::RestrictedPayload;
use crate::token::unscoped::UnscopedPayload;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Token {
    Unscoped(UnscopedPayload),
    DomainScope(DomainScopePayload),
    ProjectScope(ProjectScopePayload),
    FederationUnscoped(FederationUnscopedPayload),
    FederationProjectScope(FederationProjectScopePayload),
    FederationDomainScope(FederationDomainScopePayload),
    ApplicationCredential(ApplicationCredentialPayload),
    Restricted(RestrictedPayload),
}

impl Token {
    pub const fn user_id(&self) -> &String {
        match self {
            Self::Unscoped(x) => &x.user_id,
            Self::ProjectScope(x) => &x.user_id,
            Self::DomainScope(x) => &x.user_id,
            Self::FederationUnscoped(x) => &x.user_id,
            Self::FederationProjectScope(x) => &x.user_id,
            Self::FederationDomainScope(x) => &x.user_id,
            Self::ApplicationCredential(x) => &x.user_id,
            Self::Restricted(x) => &x.user_id,
        }
    }

    pub const fn user(&self) -> &Option<UserResponse> {
        match self {
            Self::Unscoped(x) => &x.user,
            Self::ProjectScope(x) => &x.user,
            Self::DomainScope(x) => &x.user,
            Self::FederationUnscoped(x) => &x.user,
            Self::FederationProjectScope(x) => &x.user,
            Self::FederationDomainScope(x) => &x.user,
            Self::ApplicationCredential(x) => &x.user,
            Self::Restricted(x) => &x.user,
        }
    }

    pub const fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Self::Unscoped(x) => &x.expires_at,
            Self::ProjectScope(x) => &x.expires_at,
            Self::DomainScope(x) => &x.expires_at,
            Self::FederationUnscoped(x) => &x.expires_at,
            Self::FederationProjectScope(x) => &x.expires_at,
            Self::FederationDomainScope(x) => &x.expires_at,
            Self::ApplicationCredential(x) => &x.expires_at,
            Self::Restricted(x) => &x.expires_at,
        }
    }

    pub const fn methods(&self) -> &Vec<String> {
        match self {
            Self::Unscoped(x) => &x.methods,
            Self::ProjectScope(x) => &x.methods,
            Self::DomainScope(x) => &x.methods,
            Self::FederationUnscoped(x) => &x.methods,
            Self::FederationProjectScope(x) => &x.methods,
            Self::FederationDomainScope(x) => &x.methods,
            Self::ApplicationCredential(x) => &x.methods,
            Self::Restricted(x) => &x.methods,
        }
    }

    pub const fn audit_ids(&self) -> &Vec<String> {
        match self {
            Self::Unscoped(x) => &x.audit_ids,
            Self::ProjectScope(x) => &x.audit_ids,
            Self::DomainScope(x) => &x.audit_ids,
            Self::FederationUnscoped(x) => &x.audit_ids,
            Self::FederationProjectScope(x) => &x.audit_ids,
            Self::FederationDomainScope(x) => &x.audit_ids,
            Self::ApplicationCredential(x) => &x.audit_ids,
            Self::Restricted(x) => &x.audit_ids,
        }
    }

    pub const fn project(&self) -> Option<&Project> {
        match self {
            Self::ProjectScope(x) => x.project.as_ref(),
            Self::FederationProjectScope(x) => x.project.as_ref(),
            Self::Restricted(x) => x.project.as_ref(),
            _ => None,
        }
    }

    pub const fn domain(&self) -> Option<&Domain> {
        match self {
            Self::DomainScope(x) => x.domain.as_ref(),
            Self::FederationDomainScope(x) => x.domain.as_ref(),
            _ => None,
        }
    }

    pub const fn roles(&self) -> Option<&Vec<Role>> {
        match self {
            Self::DomainScope(x) => x.roles.as_ref(),
            Self::ProjectScope(x) => x.roles.as_ref(),
            Self::FederationProjectScope(x) => x.roles.as_ref(),
            Self::FederationDomainScope(x) => x.roles.as_ref(),
            Self::Restricted(x) => x.roles.as_ref(),
            _ => None,
        }
    }
}

/// Token restriction information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TokenRestriction {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: bool,
    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: bool,
    /// Id.
    pub id: String,
    /// Optional project ID to be used with this restriction.
    pub project_id: Option<String>,
    /// Roles bound to the restriction.
    pub role_ids: Vec<String>,
    /// Optional list of full Role information.
    pub roles: Option<Vec<crate::assignment::types::Role>>,
    /// User id
    pub user_id: Option<String>,
}

pub trait TokenBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, g: Config);

    /// Extract the token from string
    fn decode(&self, credential: &str) -> Result<Token, TokenProviderError>;

    /// Extract the token from string
    fn encode(&self, token: &Token) -> Result<String, TokenProviderError>;
}

dyn_clone::clone_trait_object!(TokenBackend);
