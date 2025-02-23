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
mod error;
pub mod fernet;
pub mod fernet_utils;
pub mod project_scoped;
pub mod types;
pub mod unscoped;

use crate::config::{Config, TokenProvider as TokenProviderType};
pub use error::TokenProviderError;
use types::TokenBackend;

pub use application_credential::ApplicationCredentialToken;
pub use domain_scoped::DomainScopeToken;
pub use project_scoped::ProjectScopeToken;
pub use types::Token;
use types::TokenData;
pub use unscoped::UnscopedToken;

#[derive(Clone, Debug)]
pub struct TokenProvider {
    backend_driver: Box<dyn TokenBackend>,
}

impl TokenProvider {
    pub fn new(config: &Config) -> Result<Self, TokenProviderError> {
        let mut backend_driver = match config.token.provider {
            TokenProviderType::Fernet => fernet::FernetTokenProvider::default(),
        };
        backend_driver.set_config(config.clone());
        Ok(Self {
            backend_driver: Box::new(backend_driver),
        })
    }
}

#[async_trait]
pub trait TokenApi: Send + Sync + Clone {
    async fn validate_token(
        &self,
        credential: String,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError>;
}

#[async_trait]
impl TokenApi for TokenProvider {
    /// Validate token
    #[tracing::instrument(level = "info", skip(self))]
    async fn validate_token(
        &self,
        credential: String,
        window_seconds: Option<i64>,
    ) -> Result<Token, TokenProviderError> {
        let token = self.backend_driver.extract(credential)?;
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
}

#[cfg(test)]
mock! {
    pub TokenProvider {
        pub fn new(cfg: &Config) -> Result<Self, TokenProviderError>;
    }

    #[async_trait]
    impl TokenApi for TokenProvider {
        async fn validate_token(
            &self,
            credential: String,
            window_seconds: Option<i64>,
        ) -> Result<Token, TokenProviderError>;
    }

    impl Clone for TokenProvider {
        fn clone(&self) -> Self;
    }

}
