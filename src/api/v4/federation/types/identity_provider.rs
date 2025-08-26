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
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::api::error::KeystoneApiError;
use crate::federation::types;

/// Identity provider data
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProvider {
    pub id: String,
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub domain_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_discovery_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_client_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_types: Option<Vec<String>>,

    /// URL to fetch JsonWebKeySet.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwks_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub bound_issuer: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub default_mapping_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub provider_config: Option<Value>,
}

/// Identity provider response
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct IdentityProviderResponse {
    /// IDP object
    pub identity_provider: IdentityProvider,
}

/// Identity provider data
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderCreate {
    /// Identity provider name.
    pub name: String,

    /// Identity provider domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub domain_id: Option<String>,

    /// OIDC/OAuth2 discovery url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_discovery_url: Option<String>,

    /// OIDC/OAuth2 Client id
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_client_id: Option<String>,

    /// OIDC/OAuth2 Client secret
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_client_secret: Option<String>,

    /// OIDC response more
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_mode: Option<String>,

    /// OIDC response types
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_types: Option<Vec<String>>,

    /// Optional URL to fetch JsonWebKeySet. Must be specified for JWT authentication when
    /// discovery for the provider is not available or not standard compliant.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwks_url: Option<String>,

    /// JWT validation public keys
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    /// Bound issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub bound_issuer: Option<String>,

    /// Default mapping name that should be used by default
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub default_mapping_name: Option<String>,

    /// Additional special provider specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub provider_config: Option<Value>,
}

/// Identity provider data
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderUpdate {
    pub name: Option<String>,

    #[builder(default)]
    pub oidc_discovery_url: Option<Option<String>>,

    #[builder(default)]
    pub oidc_client_id: Option<Option<String>>,

    #[builder(default)]
    pub oidc_client_secret: Option<Option<String>>,

    #[builder(default)]
    pub oidc_response_mode: Option<Option<String>>,

    #[builder(default)]
    pub oidc_response_types: Option<Option<Vec<String>>>,

    /// Optional URL to fetch JsonWebKeySet. Must be specified for JWT authentication when
    /// discovery for the provider is not available or not standard compliant.
    #[builder(default)]
    pub jwks_url: Option<Option<String>>,

    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub bound_issuer: Option<Option<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub default_mapping_name: Option<Option<String>>,

    #[builder(default)]
    pub provider_config: Option<Option<Value>>,
}

/// Identity provider create request
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderCreateRequest {
    /// Identity provider object
    pub identity_provider: IdentityProviderCreate,
}

/// Identity provider update request
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderUpdateRequest {
    /// Identity provider object
    pub identity_provider: IdentityProviderUpdate,
}

impl From<types::IdentityProvider> for IdentityProvider {
    fn from(value: types::IdentityProvider) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain_id: value.domain_id,
            oidc_discovery_url: value.oidc_discovery_url,
            oidc_client_id: value.oidc_client_id,
            oidc_response_mode: value.oidc_response_mode,
            oidc_response_types: value.oidc_response_types,
            jwks_url: value.jwks_url,
            jwt_validation_pubkeys: value.jwt_validation_pubkeys,
            bound_issuer: value.bound_issuer,
            default_mapping_name: value.default_mapping_name,
            provider_config: value.provider_config,
        }
    }
}

impl From<IdentityProviderCreateRequest> for types::IdentityProvider {
    fn from(value: IdentityProviderCreateRequest) -> Self {
        Self {
            id: String::new(),
            name: value.identity_provider.name,
            domain_id: value.identity_provider.domain_id,
            oidc_discovery_url: value.identity_provider.oidc_discovery_url,
            oidc_client_id: value.identity_provider.oidc_client_id,
            oidc_client_secret: value.identity_provider.oidc_client_secret,
            oidc_response_mode: value.identity_provider.oidc_response_mode,
            oidc_response_types: value.identity_provider.oidc_response_types,
            jwks_url: value.identity_provider.jwks_url,
            jwt_validation_pubkeys: value.identity_provider.jwt_validation_pubkeys,
            bound_issuer: value.identity_provider.bound_issuer,
            default_mapping_name: value.identity_provider.default_mapping_name,
            provider_config: value.identity_provider.provider_config,
        }
    }
}

impl From<IdentityProviderUpdateRequest> for types::IdentityProviderUpdate {
    fn from(value: IdentityProviderUpdateRequest) -> Self {
        Self {
            name: value.identity_provider.name,
            oidc_discovery_url: value.identity_provider.oidc_discovery_url,
            oidc_client_id: value.identity_provider.oidc_client_id,
            oidc_client_secret: value.identity_provider.oidc_client_secret,
            oidc_response_mode: value.identity_provider.oidc_response_mode,
            oidc_response_types: value.identity_provider.oidc_response_types,
            jwks_url: value.identity_provider.jwks_url,
            jwt_validation_pubkeys: value.identity_provider.jwt_validation_pubkeys,
            bound_issuer: value.identity_provider.bound_issuer,
            default_mapping_name: value.identity_provider.default_mapping_name,
            provider_config: value.identity_provider.provider_config,
        }
    }
}

impl IntoResponse for types::IdentityProvider {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(IdentityProviderResponse {
                identity_provider: IdentityProvider::from(self),
            }),
        )
            .into_response()
    }
}

impl From<IdentityProviderBuilderError> for KeystoneApiError {
    fn from(err: IdentityProviderBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

/// List of Identity Providers
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct IdentityProviderList {
    /// Collection of identity provider objects
    pub identity_providers: Vec<IdentityProvider>,
}

impl IntoResponse for IdentityProviderList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Query parameters for listing federated identity providers
#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct IdentityProviderListParameters {
    /// Filters the response by IDP name.
    pub name: Option<String>,

    /// Filters the response by a domain ID.
    pub domain_id: Option<String>,
}

impl From<types::IdentityProviderListParametersBuilderError> for KeystoneApiError {
    fn from(err: types::IdentityProviderListParametersBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

impl TryFrom<IdentityProviderListParameters> for types::IdentityProviderListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: IdentityProviderListParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            domain_id: value.domain_id,
        })
    }
}
