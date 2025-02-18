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

mod error;
pub mod fernet;
pub mod fernet_utils;
pub mod types;

use crate::config::{Config, TokenProvider as TokenProviderType};
pub use error::TokenProviderError;
use types::{Token, TokenBackend};

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
    async fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError>;
}

#[async_trait]
impl TokenApi for TokenProvider {
    /// Decrypt token
    #[tracing::instrument(level = "info", skip(self))]
    async fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError> {
        self.backend_driver.decrypt(credential).await
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct FakeTokenProvider {}

#[cfg(test)]
#[async_trait]
impl TokenApi for FakeTokenProvider {
    /// Decrypt token
    #[tracing::instrument(level = "info", skip(self))]
    async fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError> {
        Ok(Token {
            user_id: String::new(),
            ..Default::default()
        })
    }
}
