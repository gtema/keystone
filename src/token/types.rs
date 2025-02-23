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

use crate::config::Config;
use crate::token::TokenProviderError;
use crate::token::application_credential::ApplicationCredentialToken;
use crate::token::domain_scoped::DomainScopeToken;
use crate::token::project_scoped::ProjectScopeToken;
use crate::token::unscoped::UnscopedToken;

#[derive(Clone, Debug)]
pub enum Token {
    Unscoped(UnscopedToken),
    DomainScope(DomainScopeToken),
    ProjectScope(ProjectScopeToken),
    ApplicationCredential(ApplicationCredentialToken),
}

pub trait TokenData {
    fn user_id(&self) -> &String;
    fn expires_at(&self) -> &DateTime<Utc>;
    fn methods(&self) -> &Vec<String>;
    fn audit_ids(&self) -> &Vec<String>;
}

impl TokenData for Token {
    fn user_id(&self) -> &String {
        match self {
            Token::Unscoped(x) => x.user_id(),
            Token::ProjectScope(x) => x.user_id(),
            Token::DomainScope(x) => x.user_id(),
            Token::ApplicationCredential(x) => x.user_id(),
        }
    }
    fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Token::Unscoped(x) => x.expires_at(),
            Token::ProjectScope(x) => x.expires_at(),
            Token::DomainScope(x) => x.expires_at(),
            Token::ApplicationCredential(x) => x.expires_at(),
        }
    }
    fn methods(&self) -> &Vec<String> {
        match self {
            Token::Unscoped(x) => x.methods(),
            Token::ProjectScope(x) => x.methods(),
            Token::DomainScope(x) => x.methods(),
            Token::ApplicationCredential(x) => x.methods(),
        }
    }
    fn audit_ids(&self) -> &Vec<String> {
        match self {
            Token::Unscoped(x) => x.audit_ids(),
            Token::ProjectScope(x) => x.audit_ids(),
            Token::DomainScope(x) => x.audit_ids(),
            Token::ApplicationCredential(x) => x.audit_ids(),
        }
    }
}

pub trait TokenBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, g: Config);

    /// Extract the token from string
    fn extract(&self, credential: String) -> Result<Token, TokenProviderError>;
}

dyn_clone::clone_trait_object!(TokenBackend);
