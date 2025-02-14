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
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::provider::Provider;
use types::{Group, GroupCreateRequest, GroupList, GroupListParameters, GroupResponse};

mod types;

pub(super) fn openapi_router<P>() -> OpenApiRouter<Arc<ServiceState<P>>>
where
    P: Provider + 'static,
{
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, remove))
}

/// List groups
#[utoipa::path(
    get,
    path = "/",
    params(GroupListParameters),
    description = "List groups",
    responses(
        (status = OK, description = "List of groups", body = GroupList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_list", level = "debug", skip(state))]
async fn list<P>(
    Query(query): Query<GroupListParameters>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    let groups: Vec<Group> = state
        .provider
        .get_identity_provider()
        .list_groups(&state.db, &query.into())
        .await
        .map_err(KeystoneApiError::identity)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(GroupList { groups })
}

/// Get single group
#[utoipa::path(
    get,
    path = "/{group_id}",
    description = "Get group by ID",
    params(),
    responses(
        (status = OK, description = "Group object", body = GroupResponse),
        (status = 404, description = "Group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_get", level = "debug", skip(state))]
async fn show<P>(
    Path(group_id): Path<String>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    state
        .provider
        .get_identity_provider()
        .get_group(&state.db, &group_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "group".into(),
                identifier: group_id,
            })
        })?
}

/// Create group
#[utoipa::path(
    post,
    path = "/",
    description = "Create new Group",
    responses(
        (status = CREATED, description = "Group object", body = GroupResponse),
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::create_group", level = "debug", skip(state))]
async fn create<P>(
    State(state): State<Arc<ServiceState<P>>>,
    Json(req): Json<GroupCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    let res = state
        .provider
        .get_identity_provider()
        .create_group(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::CREATED, res).into_response())
}

/// Delete group
#[utoipa::path(
    delete,
    path = "/{group_id}",
    description = "Delete group by ID",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "group not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="groups"
)]
#[tracing::instrument(name = "api::group_delete", level = "debug", skip(state))]
async fn remove<P>(
    Path(group_id): Path<String>,
    State(state): State<Arc<ServiceState<P>>>,
) -> Result<impl IntoResponse, KeystoneApiError>
where
    P: Provider,
{
    state
        .provider
        .get_identity_provider()
        .delete_group(&state.db, &group_id)
        .await
        .map_err(KeystoneApiError::identity)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::group::types::*;
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
        let mut api = openapi_router().with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: GroupList = serde_json::from_slice(&body).unwrap();
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

        let group = crate::identity::types::GroupCreate {
            domain_id: "domain".into(),
            name: "name".into(),
            ..Default::default()
        };

        let created_group = state
            .provider
            .get_identity_provider()
            .create_group(&DatabaseConnection::Disconnected, group)
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
                    .uri(format!("/{}", created_group.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _user: GroupResponse = serde_json::from_slice(&body).unwrap();
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

        let req = GroupCreateRequest {
            group: GroupCreate {
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
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: GroupResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.group.name, req.group.name);
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

        let group = crate::identity::types::GroupCreate {
            domain_id: "domain".into(),
            name: "name".into(),
            ..Default::default()
        };

        let created_group = state
            .provider
            .get_identity_provider()
            .create_group(&DatabaseConnection::Disconnected, group)
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
                    .uri(format!("/{}", created_group.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
