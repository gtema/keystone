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

use crate::identity::types;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Group {
    /// Group ID
    pub id: String,
    /// Group domain ID
    pub domain_id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct GroupResponse {
    /// group object
    pub group: Group,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct GroupCreate {
    /// Group domain ID
    pub domain_id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct GroupCreateRequest {
    /// Group object
    pub group: GroupCreate,
}

impl From<types::Group> for Group {
    fn from(value: types::Group) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl From<GroupCreateRequest> for types::GroupCreate {
    fn from(value: GroupCreateRequest) -> Self {
        let group = value.group;
        Self {
            id: None,
            name: group.name,
            domain_id: group.domain_id,
            extra: group.extra,
            description: group.description,
        }
    }
}

impl IntoResponse for GroupResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for types::Group {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(GroupResponse {
                group: Group::from(self),
            }),
        )
            .into_response()
    }
}

/// Groups
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct GroupList {
    /// Collection of group objects
    pub groups: Vec<Group>,
}

impl From<Vec<types::Group>> for GroupList {
    fn from(value: Vec<types::Group>) -> Self {
        let objects: Vec<Group> = value.into_iter().map(Group::from).collect();
        Self { groups: objects }
    }
}

impl IntoResponse for GroupList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct GroupListParameters {
    /// Filter users by Domain ID
    pub domain_id: Option<String>,
    /// Filter users by Name
    pub name: Option<String>,
}

impl From<GroupListParameters> for types::GroupListParameters {
    fn from(value: GroupListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
