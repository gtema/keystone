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
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::identity::types;

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct User {
    /// User ID
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Option<Value>,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub options: Option<UserOptions>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct UserOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_change_password_upon_first_use: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_password_expiry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_lockout_failure_attempts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_user_inactivity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_factor_auth_enabled: Option<bool>,
}

impl From<types::UserOptions> for UserOptions {
    fn from(value: types::UserOptions) -> Self {
        Self {
            ignore_change_password_upon_first_use: value.ignore_change_password_upon_first_use,
            ignore_password_expiry: value.ignore_password_expiry,
            ignore_lockout_failure_attempts: value.ignore_lockout_failure_attempts,
            lock_password: value.lock_password,
            ignore_user_inactivity: value.ignore_user_inactivity,
            multi_factor_auth_rules: value.multi_factor_auth_rules,
            multi_factor_auth_enabled: value.multi_factor_auth_enabled,
        }
    }
}

impl From<types::User> for User {
    fn from(value: types::User) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            enabled: value.enabled,
            extra: value.extra,
            password_expires_at: value.password_expires_at,
            options: Some(value.options.into()),
        }
    }
}

impl IntoResponse for User {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for types::User {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(User::from(self))).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct Users {
    /// Collection of user objects
    pub users: Vec<User>,
}

impl From<Vec<types::User>> for Users {
    fn from(value: Vec<types::User>) -> Self {
        let objects: Vec<User> = value.into_iter().map(User::from).collect();
        Self { users: objects }
    }
}

impl IntoResponse for Users {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct UserListParameters {
    /// Filter users by Domain ID
    pub domain_id: Option<String>,
    /// Filter users by Name
    pub name: Option<String>,
}

impl From<UserListParameters> for types::UserListParameters {
    fn from(value: UserListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
            //    limit: value.limit,
        }
    }
}
