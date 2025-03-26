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

pub mod endpoint;
pub mod service;

use async_trait::async_trait;
use dyn_clone::DynClone;
use sea_orm::DatabaseConnection;

use crate::catalog::CatalogProviderError;
use crate::config::Config;

pub use crate::catalog::types::endpoint::{
    Endpoint, EndpointBuilder, EndpointBuilderError, EndpointListParameters,
};
pub use crate::catalog::types::service::{
    Service, ServiceBuilder, ServiceBuilderError, ServiceListParameters,
};

#[async_trait]
pub trait CatalogBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List services
    async fn list_services(
        &self,
        db: &DatabaseConnection,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError>;

    /// Get single service by ID
    async fn get_service<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError>;

    /// List Endpoints
    async fn list_endpoints(
        &self,
        db: &DatabaseConnection,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError>;

    /// Get single endpoint by ID
    async fn get_endpoint<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError>;

    /// Get Catalog (Services with Endpoints)
    async fn get_catalog(
        &self,
        db: &DatabaseConnection,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError>;
}

dyn_clone::clone_trait_object!(CatalogBackend);
