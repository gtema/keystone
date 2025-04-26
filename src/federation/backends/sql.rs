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

mod identity_provider;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

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
}

#[cfg(test)]
mod tests {}
