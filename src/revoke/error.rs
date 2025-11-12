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
//! Token revocation errors.

use thiserror::Error;

use crate::revoke::backend::error::RevokeDatabaseError;

/// Revoke provider error.
#[derive(Error, Debug)]
pub enum RevokeProviderError {
    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Data (de)serialization error.
    #[error("data serialization error")]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Database provider error.
    #[error(transparent)]
    RevokeDatabase {
        /// The source of the error.
        source: RevokeDatabaseError,
    },

    /// No audit ID in the token.
    #[error("token does not have the audit_id set")]
    TokenHasNoAuditId,
}

impl From<RevokeDatabaseError> for RevokeProviderError {
    fn from(source: RevokeDatabaseError) -> Self {
        match source {
            RevokeDatabaseError::Conflict { message, .. } => Self::Conflict(message),
            _ => Self::RevokeDatabase { source },
        }
    }
}
