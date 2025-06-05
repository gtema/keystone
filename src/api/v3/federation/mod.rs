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
//! Federation management
//!
//! - IDP
//! - Mapping
//! - Auth initialization
//! - Auth callback
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod auth;
pub mod error;
pub mod identity_provider;
pub mod mapping;
pub mod oidc;
mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/identity_providers", identity_provider::openapi_router())
        .nest("/mappings", mapping::openapi_router())
        .merge(auth::openapi_router())
        .merge(oidc::openapi_router())
}
