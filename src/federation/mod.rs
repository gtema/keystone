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
pub mod types;

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

    async fn list_mappings(
        &self,
        db: &DatabaseConnection,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError>;

    async fn get_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError>;

    async fn create_mapping(
        &self,
        db: &DatabaseConnection,
        idp: Mapping,
    ) -> Result<Mapping, FederationProviderError>;

    async fn update_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError>;

    async fn delete_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    async fn get_auth_state<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError>;

    async fn create_auth_state(
        &self,
        db: &DatabaseConnection,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError>;

    async fn delete_auth_state<'a>(
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

        async fn list_mappings(
            &self,
            db: &DatabaseConnection,
            params: &MappingListParameters,
        ) -> Result<Vec<Mapping>, FederationProviderError>;

        /// Get single mapping by ID
        async fn get_mapping<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<Mapping>, FederationProviderError>;

        /// Create mapping
        async fn create_mapping(
            &self,
            db: &DatabaseConnection,
            idp: Mapping,
        ) -> Result<Mapping, FederationProviderError>;

        /// Update mapping
        async fn update_mapping<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
            idp: MappingUpdate,
        ) -> Result<Mapping, FederationProviderError>;

        /// Delete mapping
        async fn delete_mapping<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<(), FederationProviderError>;

        async fn get_auth_state<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<AuthState>, FederationProviderError>;

        async fn create_auth_state(
            &self,
            db: &DatabaseConnection,
            state: AuthState,
        ) -> Result<AuthState, FederationProviderError>;

        async fn delete_auth_state<'a>(
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

    /// List mappings
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_mappings(
        &self,
        db: &DatabaseConnection,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError> {
        self.backend_driver.list_mappings(db, params).await
    }

    /// Get single mapping by ID
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError> {
        self.backend_driver.get_mapping(db, id).await
    }

    /// Create mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_mapping(
        &self,
        db: &DatabaseConnection,
        idp: Mapping,
    ) -> Result<Mapping, FederationProviderError> {
        let mut mod_idp = idp;
        mod_idp.id = Uuid::new_v4().into();

        self.backend_driver.create_mapping(db, mod_idp).await
    }

    /// Update mapping
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn update_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
        idp: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError> {
        // TODO: Check update of idp_id to enure it belongs to the same domain
        self.backend_driver.update_mapping(db, id, idp).await
    }

    /// Delete identity provider
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_mapping<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_mapping(db, id).await
    }

    /// Get auth state by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_auth_state<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        self.backend_driver.get_auth_state(db, id).await
    }

    /// Create new auth state
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn create_auth_state(
        &self,
        db: &DatabaseConnection,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        self.backend_driver.create_auth_state(db, state).await
    }

    /// Delete auth state
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn delete_auth_state<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        self.backend_driver.delete_auth_state(db, id).await
    }
}
