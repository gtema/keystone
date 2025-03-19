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
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::error::TokenError;
use crate::api::v3::role::types::Role;
use crate::resource::types as resource_provider_types;
use crate::token::Token as BackendToken;

/// Authorization token
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct Token {
    /// A list of one or two audit IDs. An audit ID is a unique, randomly generated, URL-safe
    /// string that you can use to track a token. The first audit ID is the current audit ID for
    /// the token. The second audit ID is present for only re-scoped tokens and is the audit ID
    /// from the token before it was re-scoped. A re- scoped token is one that was exchanged for
    /// another token of the same or different scope. You can use these audit IDs to track the use
    /// of a token or chain of tokens across multiple requests and endpoints without exposing the
    /// token ID to non-privileged users.
    pub audit_ids: Vec<String>,

    /// The authentication methods, which are commonly password, token, or other methods. Indicates
    /// the accumulated set of authentication methods that were used to obtain the token. For
    /// example, if the token was obtained by password authentication, it contains password. Later,
    /// if the token is exchanged by using the token authentication method one or more times, the
    /// subsequently created tokens contain both password and token in their methods attribute.
    /// Unlike multi-factor authentication, the methods attribute merely indicates the methods that
    /// were used to authenticate the user in exchange for a token. The client is responsible for
    /// determining the total number of authentication factors.
    pub methods: Vec<String>,

    /// The date and time when the token expires.
    pub expires_at: DateTime<Utc>,

    /// A user object.
    #[builder(default)]
    pub user: User,

    /// A project object including the id, name and domain object representing the project the
    /// token is scoped to. This is only included in tokens that are scoped to a project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub project: Option<Project>,

    /// A domain object including the id and name representing the domain the token is scoped to.
    /// This is only included in tokens that are scoped to a domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub domain: Option<Domain>,

    /// A list of role objects
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub roles: Option<Vec<Role>>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct TokenResponse {
    /// Token
    pub token: Token,
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Project information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Project {
    /// Project ID
    pub id: String,
    /// Project Name
    pub name: String,

    /// project domain
    pub domain: Domain,
}

/// User information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into))]
pub struct User {
    /// User ID
    pub id: String,
    /// User Name
    pub name: String,
    /// User domain
    pub domain: Domain,
    /// User password expiry date
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// Domain information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into))]
pub struct Domain {
    /// Domain ID
    pub id: String,
    /// Domain Name
    pub name: String,
}

impl From<resource_provider_types::Domain> for Domain {
    fn from(value: resource_provider_types::Domain) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}

impl TryFrom<&BackendToken> for Token {
    type Error = TokenError;

    fn try_from(value: &BackendToken) -> Result<Self, Self::Error> {
        let mut token = TokenBuilder::default();
        token.user(UserBuilder::default().id(value.user_id()).build()?);
        token.methods(value.methods().clone());
        token.audit_ids(value.audit_ids().clone());
        token.expires_at(*value.expires_at());
        Ok(token.build()?)
    }
}
