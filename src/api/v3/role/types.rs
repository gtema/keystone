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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::assignment::types;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Role {
    /// Role ID
    pub id: String,
    /// Role domain ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,
    /// Role name
    pub name: String,
    /// Role description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RoleResponse {
    /// Role object
    pub role: Role,
}

impl From<types::Role> for Role {
    fn from(value: types::Role) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl IntoResponse for RoleResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for types::Role {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(RoleResponse {
                role: Role::from(self),
            }),
        )
            .into_response()
    }
}

/// Roles
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RoleList {
    /// Collection of role objects
    pub roles: Vec<Role>,
}

impl From<Vec<types::Role>> for RoleList {
    fn from(value: Vec<types::Role>) -> Self {
        let objects: Vec<Role> = value.into_iter().map(Role::from).collect();
        Self { roles: objects }
    }
}

impl IntoResponse for RoleList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct RoleListParameters {
    /// Filter users by Domain ID
    pub domain_id: Option<String>,
    /// Filter users by Name
    pub name: Option<String>,
}

impl From<RoleListParameters> for types::RoleListParameters {
    fn from(value: RoleListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
