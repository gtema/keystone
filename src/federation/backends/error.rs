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

use crate::federation::types::*;

#[derive(Error, Debug)]
pub enum FederationDatabaseError {
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("database error")]
    Database {
        #[from]
        source: sea_orm::DbErr,
    },

    #[error("identity provider {0} not found")]
    IdentityProviderNotFound(String),

    #[error("mapping provider {0} not found")]
    MappingNotFound(String),

    #[error("auth state {0} not found")]
    AuthStateNotFound(String),

    #[error(transparent)]
    AuthStateBuilder {
        #[from]
        source: AuthStateBuilderError,
    },

    #[error(transparent)]
    IdentityProviderBuilder {
        #[from]
        source: IdentityProviderBuilderError,
    },

    #[error(transparent)]
    MappingBuilder {
        #[from]
        source: MappingBuilderError,
    },
}
