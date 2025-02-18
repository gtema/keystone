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
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::CurrentUser;
use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::provider::Provider;
use types::{User, UserCreateRequest, UserList, UserListParameters, UserResponse};

mod types;

pub(super) fn openapi_router<P>() -> OpenApiRouter<Arc<ServiceState<P>>>
where
    P: Provider + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, remove))
}

/// List users
#[utoipa::path(
    get,
    path = "/",
    params(UserListParameters),
    description = "List users",
    responses(
        (status = OK, description = "List of users", body = UserList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip(state))]
async fn list<P>(
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    let users: Vec<User> = state
        .provider
        .get_identity_provider()
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
async fn show<P>(
    Path(user_id): Path<String>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    state
        .provider
        .get_identity_provider()
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
    path = "/",
    description = "Create new user",
    responses(
        (status = CREATED, description = "New user", body = UserResponse),
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::create_user", level = "debug", skip(state))]
async fn create<P>(
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState<P>>>,
    Json(req): Json<UserCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    let user = state
        .provider
        .get_identity_provider()
        .create_user(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::CREATED, user).into_response())
}

/// Delete user
#[utoipa::path(
    delete,
    path = "/{user_id}",
    description = "Delete user by ID",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::user_delete", level = "debug", skip(state))]
async fn remove<P>(
    Path(user_id): Path<String>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    state
        .provider
        .get_identity_provider()
        .delete_user(&state.db, &user_id)
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        middleware,
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::auth::auth;
    use crate::api::v3::user::types::*;
    use crate::config::Config;
    use crate::identity::IdentityApi;
    use crate::keystone::ServiceState;
    use crate::provider::{FakeProviderApi, Provider};

    #[tokio::test]
    async fn test_list() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let provider = FakeProviderApi::new(config.clone()).unwrap();
        let state = Arc::new(ServiceState::new(config, db, provider).unwrap());
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .route_layer(middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _users: UserList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_create() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let provider = FakeProviderApi::new(config.clone()).unwrap();
        let state = Arc::new(ServiceState::new(config, db, provider).unwrap());

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: UserCreate {
                domain_id: "domain".into(),
                name: "name".into(),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let created_user: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(created_user.user.name, user.user.name);
    }

    #[tokio::test]
    async fn test_get() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let provider = FakeProviderApi::new(config.clone()).unwrap();
        let state = Arc::new(ServiceState::new(config, db, provider).unwrap());

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = crate::identity::types::UserCreate {
            domain_id: "domain".into(),
            name: "name".into(),
            ..Default::default()
        };

        let created_user = state
            .provider
            .get_identity_provider()
            .create_user(&DatabaseConnection::Disconnected, user)
            .await
            .unwrap();

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/foo").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri(format!("/{}", created_user.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _user: UserResponse = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_delete() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let provider = FakeProviderApi::new(config.clone()).unwrap();
        let state = Arc::new(ServiceState::new(config, db, provider).unwrap());

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = crate::identity::types::UserCreate {
            domain_id: "domain".into(),
            name: "name".into(),
            ..Default::default()
        };

        let created_user = state
            .provider
            .get_identity_provider()
            .create_user(&DatabaseConnection::Disconnected, user)
            .await
            .unwrap();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{}", created_user.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
