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
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use types::{User, UserCreateRequest, UserList, UserListParameters, UserResponse};

mod types;

pub(super) fn router() -> OpenApiRouter<Arc<ServiceState>> {
    OpenApiRouter::new()
        .routes(routes!(get, delete))
        .routes(routes!(list, create))
}

/// List users
#[utoipa::path(
    get,
    path = "",
    params(UserListParameters),
    description = "List users op descr",
    responses(
        (status = OK, description = "List of users", body = UserList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip(state))]
#[axum::debug_handler]
async fn list(
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState>>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    debug!("Listing users");
    let users: Vec<User> = state
        .identity
        .list_users(&state.db, &query.into())
        .await
        .map_err(KeystoneApiError::identity)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(UserList { users })
}

/// Get single user
#[utoipa::path(
    get,
    path = "/{user_id}",
    params(),
    responses(
        (status = OK, description = "Single user", body = UserResponse),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_get", level = "debug", skip(state))]
async fn get(
    Path(user_id): Path<String>,
    State(state): State<Arc<ServiceState>>,
) -> Result<impl IntoResponse, KeystoneApiError> {
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

/// Create user
#[utoipa::path(
    post,
    path = "",
    description = "User",
    responses(
        (status = OK, description = "List of users", body = UserResponse),
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::create_list", level = "debug", skip(state))]
#[axum::debug_handler]
async fn create(
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState>>,
    Json(req): Json<UserCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    debug!("Creating users");
    let user = state
        .identity
        .create_user(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok(user.into_response())
}

/// Delete user
#[utoipa::path(
    delete,
    path = "/{user_id}",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_delete", level = "debug", skip(state))]
async fn delete(
    Path(user_id): Path<String>,
    State(state): State<Arc<ServiceState>>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    debug!("Deleting user");
    state
        .identity
        .delete_user(&state.db, &user_id)
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}
