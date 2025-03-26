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

use crate::catalog::types::{Endpoint as ProviderEndpoint, Service};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Versions {
    pub versions: Values,
}

impl IntoResponse for Versions {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Values {
    pub values: Vec<Version>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SingleVersion {
    pub version: Version,
}

impl IntoResponse for SingleVersion {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Version {
    pub id: String,
    pub status: VersionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_types: Option<Vec<MediaType>>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum VersionStatus {
    #[default]
    #[serde(rename = "stable")]
    Stable,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Link {
    pub rel: String,
    pub href: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct MediaType {
    pub base: String,
    pub r#type: String,
}

impl Default for MediaType {
    fn default() -> Self {
        Self {
            base: "application/json".into(),
            r#type: "application/vnd.openstack.identity-v3+json".into(),
        }
    }
}

/// A catalog object
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Catalog(Vec<CatalogService>);

impl IntoResponse for Catalog {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A catalog object
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct CatalogService {
    pub r#type: Option<String>,
    pub name: Option<String>,
    pub id: String,
    pub endpoints: Vec<Endpoint>,
}

impl From<(Service, Vec<ProviderEndpoint>)> for CatalogService {
    fn from(value: (Service, Vec<ProviderEndpoint>)) -> Self {
        Self {
            id: value.0.id.clone(),
            name: value.0.name.clone(),
            r#type: value.0.r#type,
            endpoints: value.1.into_iter().map(Into::into).collect(),
        }
    }
}

/// A Catalog Endpoint
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    pub id: String,
    pub url: String,
    pub interface: String,
    pub region: Option<String>,
    pub region_id: Option<String>,
}

impl From<ProviderEndpoint> for Endpoint {
    fn from(value: ProviderEndpoint) -> Self {
        Self {
            id: value.id.clone(),
            interface: value.interface.clone(),
            url: value.url.clone(),
            region: value.region_id.clone(),
            region_id: value.region_id.clone(),
        }
    }
}

impl From<Vec<(Service, Vec<ProviderEndpoint>)>> for Catalog {
    fn from(value: Vec<(Service, Vec<ProviderEndpoint>)>) -> Self {
        Self(
            value
                .into_iter()
                .map(|(srv, eps)| (srv, eps).into())
                .collect(),
        )
    }
}
