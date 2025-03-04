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
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::assignment::AssignmentApi;
use crate::keystone::ServiceState;
use types::{Role, RoleList, RoleListParameters, RoleResponse};

mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
}

/// List roles
#[utoipa::path(
    get,
    path = "/",
    params(RoleListParameters),
    description = "List roles",
    responses(
        (status = OK, description = "List of roles", body = RoleList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_list", level = "debug", skip(state))]
async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<RoleListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let roles: Vec<Role> = state
        .provider
        .get_assignment_provider()
        .list_roles(&state.db, &query.into())
        .await
        .map_err(KeystoneApiError::assignment)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(RoleList { roles })
}

/// Get single role
#[utoipa::path(
    get,
    path = "/{role_id}",
    description = "Get role by ID",
    params(),
    responses(
        (status = OK, description = "Role object", body = RoleResponse),
        (status = 404, description = "Role not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="roles"
)]
#[tracing::instrument(name = "api::role_get", level = "debug", skip(state))]
async fn show(
    Auth(user_auth): Auth,
    Path(role_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_assignment_provider()
        .get_role(&state.db, &role_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "role".into(),
                identifier: role_id,
            })
        })?
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::role::types::{
        Role as ApiRole, //GroupCreate as ApiGroupCreate, GroupCreateRequest,
        RoleList,
        RoleResponse,
    };
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Role, RoleListParameters},
    };
    use crate::config::Config;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::{Service, ServiceState};
    use crate::provider::ProviderBuilder;
    use crate::resource::MockResourceProvider;
    use crate::token::{MockTokenProvider, Token, UnscopedToken};

    use crate::tests::api::get_mocked_state_unauthed;

    fn get_mocked_state(assignment_mock: MockAssignmentProvider) -> ServiceState {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let mut token_mock = MockTokenProvider::default();
        let resource_mock = MockResourceProvider::default();
        token_mock.expect_validate_token().returning(|_, _| {
            Ok(Token::Unscoped(UnscopedToken {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        let identity_mock = MockIdentityProvider::default();

        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        Arc::new(Service::new(config, db, provider).unwrap())
    }

    #[tokio::test]
    async fn test_list() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_: &DatabaseConnection, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![Role {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(assignment_mock);

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
        let res: RoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiRole {
                id: "1".into(),
                name: "2".into(),
                // for some reason when deserializing missing value appears still as an empty
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.roles
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_: &DatabaseConnection, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(assignment_mock);

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
        let _res: RoleList = serde_json::from_slice(&body).unwrap();
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
    async fn test_get() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_get_role()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        assignment_mock
            .expect_get_role()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "bar".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(assignment_mock);

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
        let res: RoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiRole {
                id: "bar".into(),
                extra: Some(json!({})),
                ..Default::default()
            },
            res.role,
        );
    }
}
