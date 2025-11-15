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

pub mod auth_state;
pub mod identity_provider;
pub mod mapping;

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::config::Config;
use crate::federation::FederationProviderError;
use crate::keystone::ServiceState;

pub use auth_state::*;
pub use identity_provider::*;
pub use mapping::*;

#[async_trait]
pub trait FederationBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List Identity Providers
    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

    /// Get single identity provider by ID
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    /// Create Identity provider
    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProvider,
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Update Identity provider
    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    /// Delete identity provider
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    /// List Identity Providers
    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError>;

    /// Get single mapping by ID
    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError>;

    /// Create mapping
    async fn create_mapping(
        &self,
        state: &ServiceState,
        idp: Mapping,
    ) -> Result<Mapping, FederationProviderError>;

    /// Update mapping
    async fn update_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError>;

    /// Delete mapping
    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    /// Get authentication state
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError>;

    /// Create new authentication state
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError>;

    /// Delete authentication state
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    /// Cleanup expired resources
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError>;
}

dyn_clone::clone_trait_object!(FederationBackend);
