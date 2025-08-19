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

//! Federation mappings API
use axum::{
    Json, debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::federation::types::*;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

pub(crate) static DESCRIPTION: &str = r#"Federation mappings API.

Mappings define how the user attributes on the remote IDP are mapped to the local user.

Mappings with an empty domain_id are considered globals and every domain may use it. Such mappings
require the `domain_id_claim` attribute to be set to identify the domain_id for the respective
user.
"#;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, update, remove))
}

/// List federation mappings.
///
/// List available federation mappings.
///
/// Without `domain_id` specified global mappings are returned.
///
/// It is expected that listing mappings belonging to the other domain is only allowed to the admin
/// user.
#[utoipa::path(
    get,
    path = "/",
    params(MappingListParameters),
    responses(
        (status = OK, description = "List of mappings", body = MappingList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<MappingListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce("identity/mapping_list", &user_auth, to_value(&query)?, None)
        .await?;

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
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_get",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug),
    err(Debug)
)]
async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: idp_id,
            })
        })??;

    policy
        .enforce(
            "identity/mapping_show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

/// Create mapping
#[utoipa::path(
    post,
    path = "/",
    description = "Create new mapping",
    responses(
        (status = CREATED, description = "mapping object", body = MappingResponse),
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_create",
    level = "debug",
    skip(state, user_auth, policy)
)]
#[debug_handler]
async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<MappingCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/mapping_create",
            &user_auth,
            serde_json::to_value(&req.mapping)?,
            None,
        )
        .await?;

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
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<MappingUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state.db, &idp_id)
        .await?;

    policy
        .enforce(
            "identity/mapping_update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.mapping)?),
        )
        .await?;

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
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_delete",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
async fn remove(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state.db, &id)
        .await?;

    policy
        .enforce(
            "identity/mapping_delete",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    if current.is_some() {
        state
            .provider
            .get_federation_provider()
            .delete_mapping(&state.db, &id)
            .await
            .map_err(KeystoneApiError::federation)?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "mapping".to_string(),
            identifier: id.clone(),
        });
    }
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
    use tracing_test::traced_test;

    use super::*;
    use crate::config::Config;
    use crate::federation::{MockFederationProvider, types as provider_types};
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    fn get_mocked_state(
        federation_mock: MockFederationProvider,
        policy_allowed: bool,
    ) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .federation(federation_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        if policy_allowed {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock
                    .expect_enforce()
                    .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
                Ok(policy_mock)
            });
        } else {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock.expect_enforce().returning(|_, _, _, _| {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                });
                Ok(policy_mock)
            });
        }
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                policy_factory_mock,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    #[traced_test]
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
                    idp_id: "idp_id".into(),
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock, true);

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
                idp_id: "idp_id".into(),
                r#type: MappingType::default(),
                allowed_redirect_uris: None,
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                groups_claim: None,
                bound_audiences: None,
                bound_subject: None,
                bound_claims: None,
                oidc_scopes: None,
                token_user_id: None,
                token_role_ids: None,
                token_project_id: None
            }],
            res.mappings
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_mappings()
            .withf(
                |_: &DatabaseConnection, qp: &provider_types::MappingListParameters| {
                    provider_types::MappingListParameters {
                        name: Some("name".into()),
                        domain_id: Some("did".into()),
                        idp_id: Some("idp".into()),
                        ..Default::default()
                    } == *qp
                },
            )
            .returning(|_, _| {
                Ok(vec![provider_types::Mapping {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    idp_id: "idp".into(),
                    r#type: MappingType::default().into(),
                    allowed_redirect_uris: None,
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    groups_claim: None,
                    bound_audiences: None,
                    bound_subject: None,
                    bound_claims: None,
                    oidc_scopes: None,
                    token_user_id: None,
                    token_role_ids: None,
                    token_project_id: None,
                }])
            });

        let state = get_mocked_state(federation_mock, true);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name&domain_id=did&idp_id=idp")
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
    #[traced_test]
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
                    idp_id: "idp_id".into(),
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(federation_mock, true);

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
                idp_id: "idp_id".into(),
                r#type: MappingType::default(),
                allowed_redirect_uris: None,
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                groups_claim: None,
                bound_audiences: None,
                bound_subject: None,
                bound_claims: None,
                oidc_scopes: None,
                token_user_id: None,
                token_role_ids: None,
                token_project_id: None,
            },
            res.mapping,
        );
    }

    #[tokio::test]
    #[traced_test]
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

        let state = get_mocked_state(federation_mock, true);

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
    #[traced_test]
    async fn test_update() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "1")
            .returning(|_, _| {
                Ok(Some(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });

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

        let state = get_mocked_state(federation_mock, true);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingUpdateRequest {
            mapping: MappingUpdate {
                name: Some("name".into()),
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
    #[traced_test]
    async fn test_delete() {
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
        federation_mock
            .expect_delete_mapping()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(federation_mock, true);

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

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{:?}",
            response.into_body().collect().await.unwrap()
        );

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
