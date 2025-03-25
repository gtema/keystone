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

use crate::catalog::backends::error::*;
use crate::catalog::types::ServiceBuilderError;

#[derive(Error, Debug)]
pub enum CatalogProviderError {
    /// Unsupported driver
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Identity provider error
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Identity provider error
    #[error(transparent)]
    CatalogDatabase {
        #[from]
        source: CatalogDatabaseError,
    },

    #[error(transparent)]
    ServiceBuilder {
        #[from]
        source: ServiceBuilderError,
    },

    #[error("service {0} not found")]
    ServiceNotFound(String),
}

impl CatalogProviderError {
    pub fn database(source: CatalogDatabaseError) -> Self {
        match source {
            CatalogDatabaseError::ServiceNotFound(x) => Self::ServiceNotFound(x),
            _ => Self::CatalogDatabase { source },
        }
    }
}
