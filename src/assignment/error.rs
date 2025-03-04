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

use crate::assignment::backends::error::*;
use crate::assignment::types::RoleBuilderError;

#[derive(Error, Debug)]
pub enum AssignmentProviderError {
    /// Unsupported driver
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Identity provider error
    #[error("data serialization error: {}", source)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("role {0} not found")]
    RoleNotFound(String),

    /// Assignment provider error
    #[error("assignment provider database error: {}", source)]
    AssignmentDatabaseError {
        #[from]
        source: AssignmentDatabaseError,
    },

    #[error("building role data: {}", source)]
    RoleBuilderError {
        #[from]
        source: RoleBuilderError,
    },
}

impl AssignmentProviderError {
    pub fn database(source: AssignmentDatabaseError) -> Self {
        match source {
            AssignmentDatabaseError::RoleNotFound(x) => Self::RoleNotFound(x),
            _ => Self::AssignmentDatabaseError { source },
        }
    }
}
