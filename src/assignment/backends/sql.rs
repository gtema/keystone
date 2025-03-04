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
use crate::assignment::AssignmentProviderError;
use crate::config::Config;

mod assignment;
mod role;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// List roles
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list_roles(
        &self,
        db: &DatabaseConnection,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError> {
        Ok(role::list(&self.config, db, params).await?)
    }

    /// Get single role by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_role<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError> {
        Ok(role::get(&self.config, db, id).await?)
    }

    /// List role assignments
    #[tracing::instrument(level = "info", skip(self, db))]
    async fn list_assignments(
        &self,
        db: &DatabaseConnection,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        Ok(assignment::list(&self.config, db, params).await?)
    }
}
