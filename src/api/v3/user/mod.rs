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
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::group::types::{Group, GroupList};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use types::{User, UserCreateRequest, UserList, UserListParameters, UserResponse};

pub mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, remove))
        .routes(routes!(groups))
}

/// List users.
#[utoipa::path(
    get,
    path = "/",
    params(UserListParameters),
    responses(
        (status = OK, description = "List of users", body = UserList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="users"
)]
#[tracing::instrument(name = "api::user_list", level = "debug", skip_all, fields(query))]
async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<UserListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce("identity/user_list", &user_auth, to_value(&query)?, None)
        .await?;

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

/// Get single user.
#[utoipa::path(
    get,
    path = "/{user_id}",
    responses(
        (status = OK, description = "Single user", body = UserResponse),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="users"
)]
#[tracing::instrument(name = "api::user_get", level = "debug", skip_all, fields(user_id))]
async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&state.db, &user_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: user_id,
            })
        })??;

    policy
        .enforce(
            "identity/user_show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

/// Create user.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "New user", body = UserResponse),
    ),
    security(("x-auth" = [])),
    tag="users"
)]
#[tracing::instrument(name = "api::create_user", level = "debug", skip_all, fields(req))]
async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<UserCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/user_create",
            &user_auth,
            serde_json::to_value(&req.user)?,
            None,
        )
        .await?;
    let user = state
        .provider
        .get_identity_provider()
        .create_user(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::CREATED, user).into_response())
}

/// Delete user.
#[utoipa::path(
    delete,
    path = "/{user_id}",
    security(("x-auth" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="users"
)]
#[tracing::instrument(name = "api::user_delete", level = "debug", skip_all, fields(user_id))]
async fn remove(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&state.db, &user_id)
        .await?;

    policy
        .enforce(
            "identity/user_delete",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;

    state
        .provider
        .get_identity_provider()
        .delete_user(&state.db, &user_id)
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

/// List groups a user is member of.
#[utoipa::path(
    get,
    path = "/{user_id}/groups",
    responses(
        (status = OK, description = "List of user groups", body = GroupList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="users"
)]
#[tracing::instrument(
    name = "api::user_group_list",
    level = "debug",
    skip_all,
    fields(user_id)
)]
async fn groups(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_identity_provider()
        .get_user(&state.db, &user_id)
        .await?;

    policy
        .enforce(
            "identity/user_group_list",
            &user_auth,
            to_value(&current)?,
            None,
        )
        .await?;

    let groups: Vec<Group> = state
        .provider
        .get_identity_provider()
        .list_groups_for_user(&state.db, &user_id)
        .await
        .map_err(KeystoneApiError::identity)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(GroupList { groups })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::group::types::{Group as ApiGroup, GroupList};
    use crate::api::v3::user::types::{
        User as ApiUser, UserCreate as ApiUserCreate, UserCreateRequest, UserList,
        UserResponse as ApiUserResponse,
    };
    use crate::identity::{
        MockIdentityProvider,
        error::IdentityProviderError,
        types::{Group, UserCreate, UserListParameters, UserResponse},
    };

    use crate::tests::api::{get_mocked_state, get_mocked_state_unauthed};

    #[tokio::test]
    async fn test_list() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_: &DatabaseConnection, _: &UserListParameters| true)
            .returning(|_, _| {
                Ok(vec![UserResponse {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
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
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiUser {
                id: "1".into(),
                name: "2".into(),
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.users
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_list_users()
            .withf(|_: &DatabaseConnection, qp: &UserListParameters| {
                UserListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain&name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: UserList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state_unauthed();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .withf(|_: &DatabaseConnection, req: &UserCreate| {
                req.domain_id == "domain" && req.name == "name"
            })
            .returning(|_, req| {
                Ok(UserResponse {
                    id: "bar".into(),
                    domain_id: req.domain_id,
                    name: req.name,
                    ..Default::default()
                })
            });

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: ApiUserCreate {
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
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let created_user: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(created_user.user.name, user.user.name);
    }

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "bar".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .header("x-auth-token", "foo")
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
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiUser {
                id: "bar".into(),
                extra: Some(json!({})),
                ..Default::default()
            },
            res.user,
        );
    }

    #[tokio::test]
    async fn test_delete() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "bar".into(),
                    ..Default::default()
                }))
            });
        identity_mock
            .expect_delete_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("foo".into())));

        identity_mock
            .expect_delete_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .header("x-auth-token", "foo")
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
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_groups() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(UserResponse {
                    id: "foo".into(),
                    ..Default::default()
                }))
            });
        identity_mock
            .expect_list_groups_for_user()
            .withf(|_: &DatabaseConnection, uid: &str| uid == "foo")
            .returning(|_, _| {
                Ok(vec![Group {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(identity_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/groups")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiGroup {
                id: "1".into(),
                name: "2".into(),
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.groups
        );
    }
}
