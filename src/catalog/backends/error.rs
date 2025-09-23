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

use crate::catalog::types::*;

#[derive(Error, Debug)]
pub enum CatalogDatabaseError {
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error(transparent)]
    EndpointBuilder {
        #[from]
        source: EndpointBuilderError,
    },

    #[error(transparent)]
    ServiceBuilder {
        #[from]
        source: ServiceBuilderError,
    },

    #[error("service {0} not found")]
    ServiceNotFound(String),

    /// Conflict
    #[error("{0}")]
    Conflict(String),

    /// SqlError
    #[error("{0}")]
    Sql(String),

    /// Database error
    #[error(transparent)]
    Database { source: sea_orm::DbErr },
}

impl From<sea_orm::DbErr> for CatalogDatabaseError {
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
