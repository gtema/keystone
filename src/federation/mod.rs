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
#[cfg(test)]
use mockall::mock;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

pub mod backends;
pub mod error;
pub(crate) mod types;

use crate::config::Config;
use crate::federation::backends::sql::SqlBackend;
use crate::federation::error::FederationProviderError;
use crate::federation::types::*;
use crate::plugin_manager::PluginManager;

#[derive(Clone, Debug)]
pub struct FederationProvider {
    backend_driver: Box<dyn FederationBackend>,
}

#[async_trait]
pub trait FederationApi: Send + Sync + Clone {
    async fn list_identity_providers(
        &self,
        db: &DatabaseConnection,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

    async fn get_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    async fn create_identity_provider(
        &self,
        db: &DatabaseConnection,
        idp: IdentityProvider,
    ) -> Result<IdentityProvider, FederationProviderError>;

    async fn update_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    async fn delete_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;
}

#[cfg(test)]
mock! {
    pub FederationProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, FederationProviderError>;
    }

    #[async_trait]
    impl FederationApi for FederationProvider {
        async fn list_identity_providers(
            &self,
            db: &DatabaseConnection,
            params: &IdentityProviderListParameters,
        ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

        async fn get_identity_provider<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<IdentityProvider>, FederationProviderError>;

        async fn create_identity_provider(
            &self,
            db: &DatabaseConnection,
            idp: IdentityProvider,
        ) -> Result<IdentityProvider, FederationProviderError>;

        async fn update_identity_provider<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
            idp: IdentityProviderUpdate,
        ) -> Result<IdentityProvider, FederationProviderError>;

        async fn delete_identity_provider<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<(), FederationProviderError>;
    }

    impl Clone for FederationProvider {
        fn clone(&self) -> Self;
    }
}

impl FederationProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, FederationProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_federation_backend(config.federation.driver.clone())
        {
            driver.clone()
        } else {
            match config.federation.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(FederationProviderError::UnsupportedDriver(
                        config.resource.driver.clone(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl FederationApi for FederationProvider {
    /// List IDP
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_identity_providers(
        &self,
        db: &DatabaseConnection,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .list_identity_providers(db, params)
            .await
    }

    /// Get single IDP by ID
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        self.backend_driver.get_identity_provider(db, id).await
    }

    /// Create Identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_identity_provider(
        &self,
        db: &DatabaseConnection,
        idp: IdentityProvider,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let mut mod_idp = idp;
        mod_idp.id = Uuid::new_v4().into();

        self.backend_driver
            .create_identity_provider(db, mod_idp)
            .await
    }

    /// Update Identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn update_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        self.backend_driver
            .update_identity_provider(db, id, idp)
            .await
    }

    /// Delete identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_identity_provider<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_identity_provider(db, id).await
    }
}
