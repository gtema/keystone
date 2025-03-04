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

pub mod assignment;
pub mod role;

use async_trait::async_trait;
use dyn_clone::DynClone;
use sea_orm::DatabaseConnection;

use crate::assignment::AssignmentProviderError;
use crate::config::Config;

pub use crate::assignment::types::assignment::{
    Assignment, AssignmentBuilder, AssignmentBuilderError, AssignmentType,
    RoleAssignmentListParameters, RoleAssignmentListParametersBuilder,
    RoleAssignmentListParametersBuilderError,
};
pub use crate::assignment::types::role::{Role, RoleBuilder, RoleBuilderError, RoleListParameters};

#[async_trait]
pub trait AssignmentBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// List Roles
    async fn list_roles(
        &self,
        db: &DatabaseConnection,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, AssignmentProviderError>;

    /// Get single role by ID
    async fn get_role<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Role>, AssignmentProviderError>;

    /// List Role assignments
    async fn list_assignments(
        &self,
        db: &DatabaseConnection,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError>;
}

dyn_clone::clone_trait_object!(AssignmentBackend);
