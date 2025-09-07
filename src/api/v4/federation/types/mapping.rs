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
//! Federated attribute mapping types.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::api::error::KeystoneApiError;
use crate::federation::types;

/// OIDC/JWT mapping data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct Mapping {
    /// Attribute mapping ID for federated logins.
    pub id: String,

    /// Attribute mapping name for federated logins.
    pub name: String,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used by different
    /// domains. This requires `domain_id_claim` to be present. Attribute mapping can be only
    /// shared when the referred identity provider is also shared (does not set the `domain_id`
    /// attribute).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// ID of the federated identity provider for which this attribute mapping can be used.
    pub idp_id: String,

    /// Attribute mapping type ([oidc, jwt]).
    pub r#type: MappingType,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// `user_id` claim name.
    pub user_id_claim: String,

    /// `user_name` claim name.
    pub user_name_claim: String,

    /// `domain_id` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Vec<String>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<String>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Vec<String>>,

    /// Fixed user_id for which the keystone token would be issued.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_user_id: Option<String>,

    /// List of fixed roles that would be included in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_role_ids: Option<Vec<String>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_project_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct MappingResponse {
    /// IDP object
    pub mapping: Mapping,
}

/// OIDC/JWT attribute mapping create data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct MappingCreate {
    /// Attribute mapping ID for federated logins.
    pub id: Option<String>,

    /// Attribute mapping name for federated logins.
    pub name: String,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used by different
    /// domains. This requires `domain_id_claim` to be present. Attribute mapping can be only
    /// shared when the referred identity provider is also shared (does not set the `domain_id`
    /// attribute).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub domain_id: Option<String>,

    /// ID of the federated identity provider for which this attribute mapping can be used.
    pub idp_id: String,

    /// Attribute mapping type ([oidc, jwt]).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub r#type: Option<MappingType>,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// `user_id` claim name.
    pub user_id_claim: String,

    /// `user_name` claim name.
    pub user_name_claim: String,

    /// `domain_id` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub groups_claim: Option<String>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub bound_audiences: Option<Vec<String>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub bound_subject: Option<String>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub oidc_scopes: Option<Vec<String>>,

    /// Fixed user_id for which the keystone token would be issued.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub token_user_id: Option<String>,

    /// List of fixed roles that would be included in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub token_role_ids: Option<Vec<String>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub token_project_id: Option<String>,
}

/// OIDC/JWT attribute mapping update data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into))]
pub struct MappingUpdate {
    /// Attribute mapping name for federated logins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used by different
    /// domains. This requires `domain_id_claim` to be present. Attribute mapping can be only
    /// shared when the referred identity provider is also shared (does not set the `domain_id`
    /// attribute).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<Option<String>>,

    /// ID of the federated identity provider for which this attribute mapping can be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_id: Option<String>,

    /// Attribute mapping type ([oidc, jwt]).
    #[builder(default)]
    pub r#type: Option<MappingType>,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    /// `user_id` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id_claim: Option<String>,

    /// `user_name` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name_claim: Option<String>,

    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<Option<String>>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Option<Vec<String>>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<Option<String>>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    /// Fixed user_id for which the keystone token would be issued.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_user_id: Option<Option<String>>,

    /// List of fixed roles that would be included in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_role_ids: Option<Option<Vec<String>>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_project_id: Option<Option<String>>,
}

/// OIDC/JWT attribute mapping create request.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct MappingCreateRequest {
    /// Mapping object
    pub mapping: MappingCreate,
}

/// OIDC/JWT attribute mapping update request.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct MappingUpdateRequest {
    /// Mapping object
    pub mapping: MappingUpdate,
}

impl From<types::Mapping> for Mapping {
    fn from(value: types::Mapping) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain_id: value.domain_id,
            idp_id: value.idp_id,
            r#type: value.r#type.into(),
            allowed_redirect_uris: value.allowed_redirect_uris,
            user_id_claim: value.user_id_claim,
            user_name_claim: value.user_name_claim,
            domain_id_claim: value.domain_id_claim,
            groups_claim: value.groups_claim,
            bound_audiences: value.bound_audiences,
            bound_subject: value.bound_subject,
            bound_claims: value.bound_claims,
            oidc_scopes: value.oidc_scopes,
            token_user_id: value.token_user_id,
            token_role_ids: value.token_role_ids,
            token_project_id: value.token_project_id,
        }
    }
}

impl From<MappingCreateRequest> for types::Mapping {
    fn from(value: MappingCreateRequest) -> Self {
        Self {
            id: value.mapping.id.unwrap_or_else(|| Uuid::new_v4().into()),
            name: value.mapping.name,
            domain_id: value.mapping.domain_id,
            idp_id: value.mapping.idp_id,
            r#type: value.mapping.r#type.unwrap_or_default().into(),
            allowed_redirect_uris: value.mapping.allowed_redirect_uris,
            user_id_claim: value.mapping.user_id_claim,
            user_name_claim: value.mapping.user_name_claim,
            domain_id_claim: value.mapping.domain_id_claim,
            groups_claim: value.mapping.groups_claim,
            bound_audiences: value.mapping.bound_audiences,
            bound_subject: value.mapping.bound_subject,
            bound_claims: value.mapping.bound_claims,
            oidc_scopes: value.mapping.oidc_scopes,
            token_user_id: value.mapping.token_user_id,
            token_role_ids: value.mapping.token_role_ids,
            token_project_id: value.mapping.token_project_id,
        }
    }
}

impl From<MappingUpdateRequest> for types::MappingUpdate {
    fn from(value: MappingUpdateRequest) -> Self {
        Self {
            name: value.mapping.name,
            idp_id: value.mapping.idp_id,
            r#type: value.mapping.r#type.map(Into::into),
            allowed_redirect_uris: value.mapping.allowed_redirect_uris,
            user_id_claim: value.mapping.user_id_claim,
            user_name_claim: value.mapping.user_name_claim,
            domain_id_claim: value.mapping.domain_id_claim,
            groups_claim: value.mapping.groups_claim,
            bound_audiences: value.mapping.bound_audiences,
            bound_subject: value.mapping.bound_subject,
            bound_claims: value.mapping.bound_claims,
            oidc_scopes: value.mapping.oidc_scopes,
            token_user_id: value.mapping.token_user_id,
            token_role_ids: value.mapping.token_role_ids,
            token_project_id: value.mapping.token_project_id,
        }
    }
}

impl IntoResponse for types::Mapping {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(MappingResponse {
                mapping: Mapping::from(self),
            }),
        )
            .into_response()
    }
}

impl From<MappingBuilderError> for KeystoneApiError {
    fn from(err: MappingBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

/// Attribute mapping type.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MappingType {
    #[default]
    /// OIDC
    Oidc,
    /// JWT
    Jwt,
}

impl From<types::MappingType> for MappingType {
    fn from(value: types::MappingType) -> MappingType {
        match value {
            types::MappingType::Oidc => MappingType::Oidc,
            types::MappingType::Jwt => MappingType::Jwt,
        }
    }
}

impl From<MappingType> for types::MappingType {
    fn from(value: MappingType) -> types::MappingType {
        match value {
            MappingType::Oidc => types::MappingType::Oidc,
            MappingType::Jwt => types::MappingType::Jwt,
        }
    }
}

/// List of OIDC/JWT attribute mappings.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct MappingList {
    /// Collection of identity provider objects
    pub mappings: Vec<Mapping>,
}

impl IntoResponse for MappingList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Query parameters for listing OIDC/JWT attribute mappings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct MappingListParameters {
    /// Filters the response by IDP name.
    pub name: Option<String>,

    /// Filters the response by a domain ID.
    pub domain_id: Option<String>,

    /// Filters the response by a idp ID.
    pub idp_id: Option<String>,

    /// Filters the response by a mapping type.
    pub r#type: Option<MappingType>,
}

impl From<types::MappingListParametersBuilderError> for KeystoneApiError {
    fn from(err: types::MappingListParametersBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

impl TryFrom<MappingListParameters> for types::MappingListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: MappingListParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            domain_id: value.domain_id,
            idp_id: value.idp_id,
            r#type: value.r#type.map(Into::into),
        })
    }
}
