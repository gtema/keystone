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

use sea_orm::SqlErr;
use thiserror::Error;

use crate::assignment::types::*;

#[derive(Error, Debug)]
pub enum AssignmentDatabaseError {
    #[error("{0}")]
    RoleNotFound(String),

    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("error building role assignment data: {}", source)]
    AssignmentBuilder {
        #[from]
        source: AssignmentBuilderError,
    },

    #[error("error building role data: {}", source)]
    RoleBuilder {
        #[from]
        source: RoleBuilderError,
    },

    #[error(transparent)]
    Database { source: sea_orm::DbErr },

    /// Conflict
    #[error("{0}")]
    Conflict(String),

    /// SqlError
    #[error("{0}")]
    Sql(String),

    #[error("{0}")]
    InvalidAssignmentType(String),
}

impl From<sea_orm::DbErr> for AssignmentDatabaseError {
    fn from(err: sea_orm::DbErr) -> Self {
        err.sql_err().map_or_else(
            || Self::Database { source: err },
            |err| match err {
                SqlErr::UniqueConstraintViolation(descr) => Self::Conflict(descr),
                SqlErr::ForeignKeyConstraintViolation(descr) => Self::Conflict(descr),
                other => Self::Sql(other.to_string()),
            },
        )
    }
}
