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

use crate::assignment::backends::sql::SqlBackend;
use crate::assignment::error::AssignmentProviderError;
use crate::assignment::types::{
    Assignment, AssignmentBackend, Role, RoleAssignmentListParameters, RoleListParameters,
};
use crate::config::Config;
use crate::plugin_manager::PluginManager;

#[derive(Clone, Debug)]
pub struct AssignmentProvider {
    backend_driver: Box<dyn AssignmentBackend>,
}

#[async_trait]
pub trait AssignmentApi: Send + Sync + Clone {
    /// List Roles
    async fn list_roles(
        &self,
        db: &DatabaseConnection,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError>;

    async fn get_role<'a>(
        &self,
        db: &DatabaseConnection,
        role_id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError>;

    async fn list_role_assignments(
        &self,
        db: &DatabaseConnection,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;
}

#[cfg(test)]
mock! {
    pub AssignmentProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, AssignmentProviderError>;
    }

    #[async_trait]
    impl AssignmentApi for AssignmentProvider {
        async fn list_roles(
            &self,
            db: &DatabaseConnection,
            params: &RoleListParameters,
        ) -> Result<Vec<Role>, AssignmentProviderError>;

        async fn get_role<'a>(
            &self,
            db: &DatabaseConnection,
            id: &'a str,
        ) -> Result<Option<Role>, AssignmentProviderError>;

        async fn list_role_assignments(
            &self,
            db: &DatabaseConnection,
            params: &RoleAssignmentListParameters,
        ) -> Result<Vec<Assignment>, AssignmentProviderError>;
    }

    impl Clone for AssignmentProvider {
        fn clone(&self) -> Self;
    }
}

impl AssignmentProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, AssignmentProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_assignment_backend(config.assignment.driver.clone())
        {
            driver.clone()
        } else {
            match config.assignment.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(AssignmentProviderError::UnsupportedDriver(
                        config.assignment.driver.clone(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl AssignmentApi for AssignmentProvider {
    /// List roles
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_roles(
        &self,
        db: &DatabaseConnection,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError> {
        self.backend_driver.list_roles(db, params).await
    }

    /// Get single role
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn get_role<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError> {
        self.backend_driver.get_role(db, id).await
    }

    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_role_assignments(
        &self,
        db: &DatabaseConnection,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        self.backend_driver.list_assignments(db, params).await
    }
}
