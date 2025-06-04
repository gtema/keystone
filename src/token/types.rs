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
use dyn_clone::DynClone;

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
use crate::token::unscoped::UnscopedPayload;

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Unscoped(UnscopedPayload),
    DomainScope(DomainScopePayload),
    ProjectScope(ProjectScopePayload),
    FederationUnscoped(FederationUnscopedPayload),
    FederationProjectScope(FederationProjectScopePayload),
    FederationDomainScope(FederationDomainScopePayload),
    ApplicationCredential(ApplicationCredentialPayload),
}

impl Token {
    pub fn user_id(&self) -> &String {
        match self {
            Token::Unscoped(x) => &x.user_id,
            Token::ProjectScope(x) => &x.user_id,
            Token::DomainScope(x) => &x.user_id,
            Token::FederationUnscoped(x) => &x.user_id,
            Token::FederationProjectScope(x) => &x.user_id,
            Token::FederationDomainScope(x) => &x.user_id,
            Token::ApplicationCredential(x) => &x.user_id,
        }
    }

    pub fn user(&self) -> &Option<UserResponse> {
        match self {
            Token::Unscoped(x) => &x.user,
            Token::ProjectScope(x) => &x.user,
            Token::DomainScope(x) => &x.user,
            Token::FederationUnscoped(x) => &x.user,
            Token::FederationProjectScope(x) => &x.user,
            Token::FederationDomainScope(x) => &x.user,
            Token::ApplicationCredential(x) => &x.user,
        }
    }

    pub fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Token::Unscoped(x) => &x.expires_at,
            Token::ProjectScope(x) => &x.expires_at,
            Token::DomainScope(x) => &x.expires_at,
            Token::FederationUnscoped(x) => &x.expires_at,
            Token::FederationProjectScope(x) => &x.expires_at,
            Token::FederationDomainScope(x) => &x.expires_at,
            Token::ApplicationCredential(x) => &x.expires_at,
        }
    }

    pub fn methods(&self) -> &Vec<String> {
        match self {
            Token::Unscoped(x) => &x.methods,
            Token::ProjectScope(x) => &x.methods,
            Token::DomainScope(x) => &x.methods,
            Token::FederationUnscoped(x) => &x.methods,
            Token::FederationProjectScope(x) => &x.methods,
            Token::FederationDomainScope(x) => &x.methods,
            Token::ApplicationCredential(x) => &x.methods,
        }
    }

    pub fn audit_ids(&self) -> &Vec<String> {
        match self {
            Token::Unscoped(x) => &x.audit_ids,
            Token::ProjectScope(x) => &x.audit_ids,
            Token::DomainScope(x) => &x.audit_ids,
            Token::FederationUnscoped(x) => &x.audit_ids,
            Token::FederationProjectScope(x) => &x.audit_ids,
            Token::FederationDomainScope(x) => &x.audit_ids,
            Token::ApplicationCredential(x) => &x.audit_ids,
        }
    }

    pub fn project(&self) -> Option<&Project> {
        match self {
            Token::ProjectScope(x) => x.project.as_ref(),
            Token::FederationProjectScope(x) => x.project.as_ref(),
            _ => None,
        }
    }

    pub fn domain(&self) -> Option<&Domain> {
        match self {
            Token::DomainScope(x) => x.domain.as_ref(),
            Token::FederationDomainScope(x) => x.domain.as_ref(),
            _ => None,
        }
    }

    pub fn roles(&self) -> Option<&Vec<Role>> {
        match self {
            Token::DomainScope(x) => x.roles.as_ref(),
            Token::ProjectScope(x) => x.roles.as_ref(),
            Token::FederationProjectScope(x) => x.roles.as_ref(),
            Token::FederationDomainScope(x) => x.roles.as_ref(),
            _ => None,
        }
    }
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
