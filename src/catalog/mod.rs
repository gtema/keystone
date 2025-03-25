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

pub mod backends;
pub mod error;
pub(crate) mod types;

use crate::catalog::backends::sql::SqlBackend;
use crate::catalog::error::CatalogProviderError;
use crate::catalog::types::{
    CatalogBackend, Endpoint, EndpointListParameters, Service, ServiceListParameters,
};
use crate::config::Config;
use crate::plugin_manager::PluginManager;

#[derive(Clone, Debug)]
pub struct CatalogProvider {
    backend_driver: Box<dyn CatalogBackend>,
}

#[async_trait]
pub trait CatalogApi: Send + Sync + Clone {
    async fn list_services(
        &self,
        db: &DatabaseConnection,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError>;

    async fn get_service<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError>;

    async fn list_endpoints(
        &self,
        db: &DatabaseConnection,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError>;

    async fn get_endpoint<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError>;

    async fn get_catalog(
        &self,
        db: &DatabaseConnection,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;
}

#[cfg(test)]
mock! {
    pub CatalogProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, CatalogProviderError>;
    }

    #[async_trait]
    impl CatalogApi for CatalogProvider {
        async fn list_services(
            &self,
            db: &DatabaseConnection,
            params: &ServiceListParameters
        ) -> Result<Vec<Service>, CatalogProviderError>;

        async fn get_service<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<Service>, CatalogProviderError>;

        async fn list_endpoints(
            &self,
            db: &DatabaseConnection,
            params: &EndpointListParameters,
        ) -> Result<Vec<Endpoint>, CatalogProviderError>;

        async fn get_endpoint<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<Endpoint>, CatalogProviderError>;

        async fn get_catalog(
            &self,
            db: &DatabaseConnection,
            enabled: bool,
        ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;

    }

    impl Clone for CatalogProvider {
        fn clone(&self) -> Self;
    }
}

impl CatalogProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, CatalogProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_catalog_backend(config.catalog.driver.clone())
        {
            driver.clone()
        } else {
            match config.resource.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(CatalogProviderError::UnsupportedDriver(
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
impl CatalogApi for CatalogProvider {
    /// List services
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_services(
        &self,
        db: &DatabaseConnection,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError> {
        self.backend_driver.list_services(db, params).await
    }

    /// Get single service by ID
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_service<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        self.backend_driver.get_service(db, id).await
    }

    /// List Endpoints
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_endpoints(
        &self,
        db: &DatabaseConnection,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        self.backend_driver.list_endpoints(db, params).await
    }

    /// Get single endpoint by ID
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_endpoint<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        self.backend_driver.get_endpoint(db, id).await
    }

    /// Get catalog
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_catalog(
        &self,
        db: &DatabaseConnection,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        self.backend_driver.get_catalog(db, enabled).await
    }
}
