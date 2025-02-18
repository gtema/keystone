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

use crate::config::Config;
use crate::error::KeystoneError;
use crate::identity::{IdentityApi, IdentityProvider};
use crate::plugin_manager::PluginManager;
use crate::token::{TokenApi, TokenProvider};
#[cfg(test)]
use crate::{identity::FakeIdentityProvider, token::FakeTokenProvider};

pub trait Provider: Clone + Send + Sync {
    fn get_identity_provider(&self) -> &impl IdentityApi;
    fn get_token_provider(&self) -> &impl TokenApi;
}

#[derive(Clone)]
pub struct ProviderApi {
    pub config: Config,
    identity: IdentityProvider,
    token: TokenProvider,
}

impl ProviderApi {
    pub fn new(cfg: Config, plugin_manager: PluginManager) -> Result<Self, KeystoneError> {
        let identity_provider = IdentityProvider::new(&cfg, &plugin_manager)?;
        let token_provider = TokenProvider::new(&cfg)?;

        Ok(Self {
            config: cfg,
            identity: identity_provider,
            token: token_provider,
        })
    }
}

impl Provider for ProviderApi {
    fn get_identity_provider(&self) -> &impl IdentityApi {
        &self.identity
    }

    fn get_token_provider(&self) -> &impl TokenApi {
        &self.token
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct FakeProviderApi {
    pub config: Config,
    identity: FakeIdentityProvider,
    token: FakeTokenProvider,
}

#[cfg(test)]
impl FakeProviderApi {
    pub fn new(cfg: Config) -> Result<Self, KeystoneError> {
        let identity_provider = FakeIdentityProvider::default();
        let token_provider = FakeTokenProvider::default();

        Ok(Self {
            config: cfg,
            identity: identity_provider,
            token: token_provider,
        })
    }
}

#[cfg(test)]
impl Provider for FakeProviderApi {
    fn get_identity_provider(&self) -> &impl IdentityApi {
        &self.identity
    }

    fn get_token_provider(&self) -> &impl TokenApi {
        &self.token
    }
}
