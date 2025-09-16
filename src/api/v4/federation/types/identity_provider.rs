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
//! Federated identity provider types.
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
    /// The ID of the federated identity provider.
    pub id: String,

    /// The Name of the federated identity provider.
    pub name: String,

    /// The ID of the domain this identity provider belongs to. Empty value identifies that the
    /// identity provider can be used by other domains as well.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub domain_id: Option<String>,

    /// OIDC discovery endpoint for the identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_discovery_url: Option<String>,

    /// The oidc `client_id` to use for the private client. The `client_secret` is never returned
    /// and can be only overwritten.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_client_id: Option<String>,

    /// The oidc response mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_mode: Option<String>,

    /// List of supported response types.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub oidc_response_types: Option<Vec<String>>,

    /// URL to fetch JsonWebKeySet. This must be set for "jwt" mapping when the provider does not
    /// provide discovery endpoint or when it is not standard compliant.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwks_url: Option<String>,

    /// List of the jwt validation public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    /// The bound issuer that is verified when using the identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub bound_issuer: Option<String>,

    /// Default attribute mapping name which is automatically used when no mapping is explicitly
    /// requested. The referred attribute mapping must exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub default_mapping_name: Option<String>,

    /// Additional provider configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(value_type = Object)]
    pub provider_config: Option<Value>,
}

/// Identity provider response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct IdentityProviderResponse {
    /// Identity provider object.
    pub identity_provider: IdentityProvider,
}

/// Identity provider data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderCreate {
    // TODO: add ID
    /// Identity provider name.
    pub name: String,

    /// The ID of the domain this identity provider belongs to. Empty value identifies that the
    /// identity provider can be used by other domains as well.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub domain_id: Option<String>,

    /// OIDC discovery endpoint for the identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub oidc_discovery_url: Option<String>,

    /// The oidc `client_id` to use for the private client.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub oidc_client_id: Option<String>,

    /// The oidc `client_secret` to use for the private client. It is never returned back.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub oidc_client_secret: Option<String>,

    /// The oidc response mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub oidc_response_mode: Option<String>,

    /// List of supported response types.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub oidc_response_types: Option<Vec<String>>,

    /// Optional URL to fetch JsonWebKeySet. Must be specified for JWT authentication when
    /// discovery for the provider is not available or not standard compliant.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub jwks_url: Option<String>,

    /// List of the jwt validation public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    /// The bound issuer that is verified when using the identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub bound_issuer: Option<String>,

    /// Default attribute mapping name which is automatically used when no mapping is explicitly
    /// requested. The referred attribute mapping must exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(nullable = false)]
    pub default_mapping_name: Option<String>,

    /// Additional special provider specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    #[schema(value_type = Object)]
    #[schema(nullable = false)]
    pub provider_config: Option<Value>,
}

/// New identity provider data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderUpdate {
    /// The new name of the federated identity provider.
    pub name: Option<String>,

    /// The new OIDC discovery endpoint for the identity provider.
    #[builder(default)]
    pub oidc_discovery_url: Option<Option<String>>,

    /// The new oidc `client_id` to use for the private client.
    #[builder(default)]
    pub oidc_client_id: Option<Option<String>>,

    /// The new oidc `client_secret` to use for the private client.
    #[builder(default)]
    pub oidc_client_secret: Option<Option<String>>,

    /// The new oidc response mode.
    #[builder(default)]
    pub oidc_response_mode: Option<Option<String>>,

    /// The new oidc response mode.
    #[builder(default)]
    pub oidc_response_types: Option<Option<Vec<String>>>,

    /// New URL to fetch JsonWebKeySet. This must be set for "jwt" mapping when the provider does not
    /// provide discovery endpoint or when it is not standard compliant.
    #[builder(default)]
    pub jwks_url: Option<Option<String>>,

    /// The list of the jwt validation public keys.
    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Option<Vec<String>>>,

    /// The new bound issuer that is verified when using the identity provider.
    #[builder(default)]
    pub bound_issuer: Option<Option<String>>,

    /// New default attribute mapping name which is automatically used when no mapping is explicitly
    /// requested. The referred attribute mapping must exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub default_mapping_name: Option<Option<String>>,

    /// New additional provider configuration.
    #[builder(default)]
    #[schema(value_type = Object)]
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

/// List of Identity Providers.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct IdentityProviderList {
    /// Collection of identity provider objects.
    pub identity_providers: Vec<IdentityProvider>,
}

impl IntoResponse for IdentityProviderList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Query parameters for listing federated identity providers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct IdentityProviderListParameters {
    /// Filters the response by IDP name.
    #[param(nullable = false)]
    pub name: Option<String>,

    /// Filters the response by a domain ID.
    #[param(nullable = false)]
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
