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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::identity::types as identity_provider_types;
use crate::resource::types::{Domain, Project};

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("building authentication information: {source}")]
    AuthenticatedInfoBuilder {
        #[from]
        source: AuthenticatedInfoBuilderError,
    },

    #[error("The request you have made requires authentication.")]
    Unauthorized,
}

/// Information about successful authentication
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(into, strip_option))]
pub struct AuthenticatedInfo {
    pub user_id: String,
    #[builder(default)]
    pub user: Option<identity_provider_types::UserResponse>,
    #[builder(default)]
    pub user_domain: Option<Domain>,
    #[builder(default)]
    pub methods: Vec<String>,
    #[builder(default)]
    pub audit_ids: Vec<String>,
    #[builder(default)]
    pub idp_id: Option<String>,
    #[builder(default)]
    pub protocol_id: Option<String>,
}

impl AuthenticatedInfo {
    pub fn builder() -> AuthenticatedInfoBuilder {
        AuthenticatedInfoBuilder::default()
    }

    pub fn validate(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum AuthzInfo {
    Unscoped,
    Project(Project),
    Domain(Domain),
}

impl AuthzInfo {
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match self {
            AuthzInfo::Unscoped => {}
            AuthzInfo::Project(project) => {
                if !project.enabled {
                    return Err(AuthenticationError::Unauthorized);
                }
            }
            AuthzInfo::Domain(domain) => {
                if !domain.enabled {
                    return Err(AuthenticationError::Unauthorized);
                }
            }
        }
        Ok(())
    }
}
