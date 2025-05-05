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
    Json, debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v3::federation::types::*;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, update, remove))
}

/// List mappings
#[utoipa::path(
    get,
    path = "/",
    params(MappingListParameters),
    description = "List federation mappings",
    responses(
        (status = OK, description = "List of mappings", body = MappingList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_list", level = "debug", skip(state, _user_auth))]
async fn list(
    Auth(_user_auth): Auth,
    Query(query): Query<MappingListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let mappings: Vec<Mapping> = state
        .provider
        .get_federation_provider()
        .list_mappings(&state.db, &query.try_into()?)
        .await
        .map_err(KeystoneApiError::federation)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(MappingList { mappings })
}

/// Get single mapping
#[utoipa::path(
    get,
    path = "/{idp_id}",
    description = "Get mapping by ID",
    params(),
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_get", level = "debug", skip(state))]
async fn show(
    Auth(user_auth): Auth,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_federation_provider()
        .get_mapping(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })?
}

/// Create mapping
#[utoipa::path(
    post,
    path = "/",
    description = "Create new mapping",
    responses(
        (status = CREATED, description = "mapping object", body = MappingResponse),
    ),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_create", level = "debug", skip(state))]
#[debug_handler]
async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<MappingCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let res = state
        .provider
        .get_federation_provider()
        .create_mapping(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::federation)?;
    Ok((StatusCode::CREATED, res).into_response())
}

/// Update single mapping
#[utoipa::path(
    put,
    path = "/{idp_id}",
    description = "Update existing mapping",
    params(),
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_update", level = "debug", skip(state))]
async fn update(
    Auth(user_auth): Auth,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<MappingUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let res = state
        .provider
        .get_federation_provider()
        .update_mapping(&state.db, &idp_id, req.into())
        .await
        .map_err(KeystoneApiError::federation)?;
    Ok(res.into_response())
}

/// Delete Identity provider
#[utoipa::path(
    delete,
    path = "/{idp_id}",
    description = "Delete mapping by ID",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_delete", level = "debug", skip(state))]
async fn remove(
    Auth(user_auth): Auth,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_federation_provider()
        .delete_mapping(&state.db, &id)
        .await
        .map_err(KeystoneApiError::federation)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;

    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::*;
    use crate::config::Config;
    use crate::federation::{
        MockFederationProvider, error::FederationProviderError, types as provider_types,
    };
    use crate::keystone::{Service, ServiceState};
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedToken};

    fn get_mocked_state(federation_mock: MockFederationProvider) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _| {
            Ok(Token::Unscoped(UnscopedToken {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });

        let provider = Provider::mocked_builder()
            .federation(federation_mock)
            .token(token_mock)
            .build()
            .unwrap();

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_mappings()
            .withf(|_: &DatabaseConnection, _: &provider_types::MappingListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::Mapping {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock);

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
        let res: MappingList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![Mapping {
                id: "id".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            }],
            res.mappings
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_mappings()
            .withf(
                |_: &DatabaseConnection, qp: &provider_types::MappingListParameters| {
                    provider_types::MappingListParameters {
                        name: Some("name".into()),
                        domain_id: Some("did".into()),
                        idp: Some("idp".into()),
                    } == *qp
                },
            )
            .returning(|_, _| {
                Ok(vec![provider_types::Mapping {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    idp: Some("idp".into())..Default::default(),
                }])
            });

        let state = get_mocked_state(federation_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name&domain_id=did")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: MappingList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_get() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        federation_mock
            .expect_get_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(federation_mock);

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
        let res: MappingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            Mapping {
                id: "bar".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                oidc_discovery_url: None,
                oidc_client_id: None,
                oidc_response_mode: None,
                oidc_response_types: None,
                jwt_validation_pubkeys: None,
                bound_issuer: None,
                provider_config: None
            },
            res.mapping,
        );
    }

    #[tokio::test]
    async fn test_create() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_create_mapping()
            .withf(|_: &DatabaseConnection, req: &provider_types::Mapping| req.name == "name")
            .returning(|_, _| {
                Ok(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
            });

        let state = get_mocked_state(federation_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingCreateRequest {
            mapping: MappingCreate {
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mapping.name, req.mapping.name);
        assert_eq!(res.mapping.domain_id, req.mapping.domain_id);
    }

    #[tokio::test]
    async fn test_update() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_update_mapping()
            .withf(
                |_: &DatabaseConnection, id: &'_ str, req: &provider_types::MappingUpdate| {
                    id == "1" && req.name == Some("name".to_string())
                },
            )
            .returning(|_, _, _| {
                Ok(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
            });

        let state = get_mocked_state(federation_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingUpdateRequest {
            mapping: MappingUpdate {
                name: Some("name".into()),
                oidc_client_id: Some(None),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: MappingResponse = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_delete() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_delete_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Err(FederationProviderError::MappingNotFound("foo".into())));

        federation_mock
            .expect_delete_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(federation_mock);

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
}
