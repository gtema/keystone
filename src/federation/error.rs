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

use thiserror::Error;

use crate::federation::backends::error::*;

#[derive(Error, Debug)]
pub enum FederationProviderError {
    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Identity provider error.
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// IDP not found.
    #[error("identity provider {0} not found")]
    IdentityProviderNotFound(String),

    /// IDP mapping not found.
    #[error("mapping {0} not found")]
    MappingNotFound(String),

    /// Use of token_user_id requires domain_id to be set.
    #[error("`mapping.domain_id` must be set")]
    MappingTokenUserDomainUnset,

    /// Use of token_project_id requires domain_id to be set.
    #[error("`mapping.domain_id` must be set")]
    MappingTokenProjectDomainUnset,

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Identity provider error.
    #[error(transparent)]
    FederationDatabase { source: FederationDatabaseError },
}

impl From<FederationDatabaseError> for FederationProviderError {
    fn from(source: FederationDatabaseError) -> Self {
        match source {
            FederationDatabaseError::IdentityProviderNotFound(x) => {
                Self::IdentityProviderNotFound(x)
            }
            FederationDatabaseError::MappingNotFound(x) => Self::MappingNotFound(x),
            FederationDatabaseError::Conflict(x) => Self::Conflict(x),
            FederationDatabaseError::Serde { source } => Self::Serde { source },
            _ => Self::FederationDatabase { source },
        }
    }
}
