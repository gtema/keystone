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

pub mod domain;

use async_trait::async_trait;
use dyn_clone::DynClone;
use sea_orm::DatabaseConnection;

use crate::config::Config;
use crate::resource::ResourceProviderError;

pub use crate::resource::types::domain::{Domain, DomainBuilder, DomainBuilderError};

#[async_trait]
pub trait ResourceBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// Get single domain by ID
    async fn get_domain(
        &self,
        db: &DatabaseConnection,
        domain_id: String,
    ) -> Result<Option<Domain>, ResourceProviderError>;
}

dyn_clone::clone_trait_object!(ResourceBackend);
