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

pub mod identity_provider;

use async_trait::async_trait;
use dyn_clone::DynClone;
use sea_orm::DatabaseConnection;

use crate::config::Config;
use crate::federation::FederationProviderError;

pub use identity_provider::*;

#[async_trait]
pub trait FederationBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List Identity Providers
    async fn list_identity_providers(
        &self,
        db: &DatabaseConnection,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

    /// Get single identity provider by ID
    async fn get_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    /// Create Identity provider
    async fn create_identity_provider(
        &self,
        db: &DatabaseConnection,
        idp: IdentityProvider,
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Update Identity provider
    async fn update_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Delete identity provider
    async fn delete_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;
}

dyn_clone::clone_trait_object!(FederationBackend);
