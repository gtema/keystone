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

use crate::identity::error::IdentityProviderPasswordHashError;
use crate::identity::types::*;

#[derive(Error, Debug)]
pub enum IdentityDatabaseError {
    #[error("corrupted database entries for user {0}")]
    MalformedUser(String),

    #[error("{0}")]
    UserNotFound(String),

    #[error("{0}")]
    GroupNotFound(String),

    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("building user response data")]
    UserBuilderError {
        #[from]
        source: UserResponseBuilderError,
    },

    #[error("building user federation")]
    FederatedUserBuilderError {
        #[from]
        source: FederationBuilderError,
    },

    /// Conflict
    #[error("{0}")]
    Conflict(String),

    /// SqlError
    #[error("{0}")]
    Sql(String),

    #[error(transparent)]
    Database { source: sea_orm::DbErr },

    #[error("password hashing error")]
    PasswordHash {
        #[from]
        source: IdentityProviderPasswordHashError,
    },

    #[error("either user id or user name with user domain id or name must be given")]
    UserIdOrNameWithDomain,
}

impl From<sea_orm::DbErr> for IdentityDatabaseError {
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
