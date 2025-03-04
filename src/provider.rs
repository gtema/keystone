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
use derive_builder::Builder;
use mockall_double::double;

use crate::assignment::AssignmentApi;
#[double]
use crate::assignment::AssignmentProvider;
use crate::config::Config;
use crate::error::KeystoneError;
use crate::identity::IdentityApi;
#[double]
use crate::identity::IdentityProvider;
use crate::plugin_manager::PluginManager;
use crate::resource::ResourceApi;
#[double]
use crate::resource::ResourceProvider;
use crate::token::TokenApi;
#[double]
use crate::token::TokenProvider;

//pub trait Provider: Clone + Send + Sync {
//    fn get_identity_provider(&self) -> &impl IdentityApi;
//    fn get_token_provider(&self) -> &impl TokenApi;
//}

#[derive(Builder, Clone)]
// It is necessary to use the owned pattern since otherwise builder invokes clone which immediately
// confuses mockall used in tests
#[builder(pattern = "owned")]
pub struct Provider {
    pub config: Config,
    assignment: AssignmentProvider,
    identity: IdentityProvider,
    resource: ResourceProvider,
    token: TokenProvider,
}

impl Provider {
    pub fn new(cfg: Config, plugin_manager: PluginManager) -> Result<Self, KeystoneError> {
        let assignment_provider = AssignmentProvider::new(&cfg, &plugin_manager)?;
        let identity_provider = IdentityProvider::new(&cfg, &plugin_manager)?;
        let resource_provider = ResourceProvider::new(&cfg, &plugin_manager)?;
        let token_provider = TokenProvider::new(&cfg)?;

        Ok(Self {
            config: cfg,
            assignment: assignment_provider,
            identity: identity_provider,
            resource: resource_provider,
            token: token_provider,
        })
    }

    pub fn get_assignment_provider(&self) -> &impl AssignmentApi {
        &self.assignment
    }

    pub fn get_identity_provider(&self) -> &impl IdentityApi {
        &self.identity
    }

    pub fn get_resource_provider(&self) -> &impl ResourceApi {
        &self.resource
    }

    pub fn get_token_provider(&self) -> &impl TokenApi {
        &self.token
    }
}
