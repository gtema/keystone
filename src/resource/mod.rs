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

use crate::config::Config;
use crate::plugin_manager::PluginManager;
use crate::resource::backends::sql::SqlBackend;
use crate::resource::error::ResourceProviderError;
use crate::resource::types::{Domain, Project, ResourceBackend};

#[derive(Clone, Debug)]
pub struct ResourceProvider {
    backend_driver: Box<dyn ResourceBackend>,
}

#[async_trait]
pub trait ResourceApi: Send + Sync + Clone {
    async fn get_domain<'a>(
        &self,
        db: &DatabaseConnection,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    async fn find_domain_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    async fn get_project<'a>(
        &self,
        db: &DatabaseConnection,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    async fn get_project_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;
}

#[cfg(test)]
mock! {
    pub ResourceProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, ResourceProviderError>;
    }

    #[async_trait]
    impl ResourceApi for ResourceProvider {
        async fn get_domain<'a>(
            &self,
            db: &DatabaseConnection,
            domain_id: &'a str,
        ) -> Result<Option<Domain>, ResourceProviderError>;

         async fn find_domain_by_name<'a>(
             &self,
             db: &DatabaseConnection,
             domain_name: &'a str,
         ) -> Result<Option<Domain>, ResourceProviderError>;

        async fn get_project<'a>(
            &self,
            db: &DatabaseConnection,
            project_id: &'a str,
        ) -> Result<Option<Project>, ResourceProviderError>;

        async fn get_project_by_name<'a>(
            &self,
            db: &DatabaseConnection,
            name: &'a str,
            domain_id: &'a str,
        ) -> Result<Option<Project>, ResourceProviderError>;

    }

    impl Clone for ResourceProvider {
        fn clone(&self) -> Self;
    }
}

impl ResourceProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, ResourceProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_resource_backend(config.resource.driver.clone())
        {
            driver.clone()
        } else {
            match config.resource.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(ResourceProviderError::UnsupportedDriver(
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
impl ResourceApi for ResourceProvider {
    /// Get single domain
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_domain<'a>(
        &self,
        db: &DatabaseConnection,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver.get_domain(db, domain_id).await
    }

    /// Get single domain by its name
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn find_domain_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(db, domain_name)
            .await
    }

    /// Get single project
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_project<'a>(
        &self,
        db: &DatabaseConnection,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver.get_project(db, project_id).await
    }

    /// Get single project by Name and Domain ID
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_project_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project_by_name(db, name, domain_id)
            .await
    }
}
