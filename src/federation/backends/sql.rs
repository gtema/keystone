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
use sea_orm::DatabaseConnection;

use super::super::types::*;
use crate::config::Config;
use crate::federation::FederationProviderError;

mod auth_state;
mod identity_provider;
mod mapping;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

#[async_trait]
impl FederationBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// List IDPs
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list_identity_providers(
        &self,
        db: &DatabaseConnection,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::list(&self.config, db, params).await?)
    }

    /// Get single IDP by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::get(&self.config, db, id).await?)
    }

    /// Create Identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_identity_provider(
        &self,
        db: &DatabaseConnection,
        idp: IdentityProvider,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::create(&self.config, db, idp).await?)
    }

    /// Update Identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn update_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::update(&self.config, db, id, idp).await?)
    }

    /// Delete identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        identity_provider::delete(&self.config, db, id)
            .await
            .map_err(FederationProviderError::database)
    }

    /// List Mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list_mappings(
        &self,
        db: &DatabaseConnection,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        Ok(mapping::list(&self.config, db, params).await?)
    }

    /// Get single mapping by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        Ok(mapping::get(&self.config, db, id).await?)
    }

    /// Create mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_mapping(
        &self,
        db: &DatabaseConnection,
        idp: Mapping,
    ) -> Result<Mapping, FederationProviderError> {
        Ok(mapping::create(&self.config, db, idp).await?)
    }

    /// Update mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn update_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError> {
        Ok(mapping::update(&self.config, db, id, idp).await?)
    }

    /// Delete mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        mapping::delete(&self.config, db, id)
            .await
            .map_err(FederationProviderError::database)
    }

    /// Get auth state by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_auth_state<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        Ok(auth_state::get(&self.config, db, id).await?)
    }

    /// Create new auth state
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_auth_state(
        &self,
        db: &DatabaseConnection,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        Ok(auth_state::create(&self.config, db, state).await?)
    }

    /// Delete auth state
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_auth_state<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        auth_state::delete(&self.config, db, id)
            .await
            .map_err(FederationProviderError::database)
    }
}

#[cfg(test)]
mod tests {}
