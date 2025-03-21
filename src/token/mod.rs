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

pub mod application_credential;
pub mod domain_scoped;
pub mod error;
pub mod fernet;
pub mod fernet_utils;
pub mod project_scoped;
pub mod types;
pub mod unscoped;

use crate::config::{Config, TokenProvider as TokenProviderType};
use crate::resource::types::{Domain, Project};
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
    async fn validate_token<'a>(
        &self,
        credential: &'a str,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError>;

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
        let token = if let Some(project) = &project {
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
                    .build()?,
            )
        } else if let Some(domain) = &domain {
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
    }

    impl Clone for TokenProvider {
        fn clone(&self) -> Self;
    }

}
