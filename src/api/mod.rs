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
//! Keystone API
//!
use axum::{
    http::{HeaderMap, header},
    response::IntoResponse,
};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub(crate) mod common;
pub mod error;
pub mod types;
pub mod v3;

use crate::api::types::*;

#[derive(OpenApi)]
#[openapi(info(version = "3.14.0"))]
pub struct ApiDoc;

pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/v3", v3::openapi_router())
        .routes(routes!(version))
}

/// Versions
#[utoipa::path(
    get,
    path = "/",
    description = "Version discovery",
    responses(
        (status = OK, description = "Versions", body = Versions),
    ),
    tag = "version"
)]
async fn version(headers: HeaderMap) -> Result<impl IntoResponse, KeystoneApiError> {
    let host = headers
        .get(header::HOST)
        .and_then(|header| header.to_str().ok())
        .unwrap_or("localhost");

    let link = Link {
        rel: "self".into(),
        href: format!("http://{}/v3", host),
    };
    let version = Version {
        id: "v3.14".into(),
        status: VersionStatus::Stable,
        links: Some(vec![link]),
        media_types: Some(vec![MediaType::default()]),
        ..Default::default()
    };
    let res = Versions {
        versions: Values {
            values: vec![version],
        },
    };
    Ok(res)
}
