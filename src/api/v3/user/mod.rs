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
    extract::{Path, Query, State},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use types::{User, UserListParameters, Users};

mod types;

pub(super) fn router() -> OpenApiRouter<Arc<ServiceState>> {
    OpenApiRouter::new()
        .routes(routes!(get))
        .routes(routes!(list))
}

/// List users
#[utoipa::path(
    get,
    path = "",
    params(UserListParameters),
    description = "List users op descr",
    responses(
        (status = OK, description = "List of users", body = Users),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip(state))]
#[axum::debug_handler]
async fn list(
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState>>,
) -> impl IntoResponse {
    debug!("Listing users");
    let users: Vec<User> = state
        .identity
        .list_users(&state.db, &query.into())
        .await
        .unwrap()
        .into_iter()
        .map(Into::into)
        .collect();
    Users { users }
}

/// Get single user
#[utoipa::path(
    get,
    path = "/{user_id}",
    params(),
    responses(
        (status = OK, description = "Single user", body = User),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_get", level = "debug", skip(state))]
async fn get(
    Path(user_id): Path<String>,
    State(state): State<Arc<ServiceState>>,
) -> impl IntoResponse {
    debug!("Fetching user details");
    state
        .identity
        .get_user(&state.db, &user_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: user_id,
            })
        })?
}
