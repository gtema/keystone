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
use chrono::{DateTime, Utc};
use dyn_clone::DynClone;

use crate::config::Config;
use crate::token::TokenProviderError;

#[derive(Clone, Debug, Default)]
pub struct Token {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub project_id: Option<String>,
    pub domain_id: Option<String>,
    pub trust_id: Option<String>,
    pub application_credential_id: Option<String>,
    pub access_token_id: Option<String>,
    pub system: Option<String>,
    pub federated_group_ids: Option<Vec<String>>,
}

#[async_trait]
pub trait TokenBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, g: Config);

    async fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError>;
}

dyn_clone::clone_trait_object!(TokenBackend);
