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

//! Identity providers API
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
use crate::api::v3::federation::types::*;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

pub(crate) static DESCRIPTION: &str = r#"Identity providers API.

Identity provider resource allows to federate users from an external Identity Provider (i.e.
Keycloak, Azure AD, etc.).

Using the Identity provider requires creation of the mapping, which describes how to map attributes
of the remote Idp to local users.

Identity provider with an empty domain_id are considered globals and every domain may use it with
appropriate mapping.
"#;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(show, update, remove))
}

/// List identity providers.
///
/// List identity providers. Without any filters only global identity providers are returned.
/// With the `domain_id` identity providers owned by the specified identity provider are returned.
///
/// It is expected that only global or owned identity providers can be returned, while an admin
/// user is able to list all providers.
#[utoipa::path(
    get,
    path = "/",
    params(IdentityProviderListParameters),
    responses(
        (status = OK, description = "List of identity providers", body = IdentityProviderList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<IdentityProviderListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/identity_provider_list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let identity_providers: Vec<IdentityProvider> = state
        .provider
        .get_federation_provider()
        .list_identity_providers(&state.db, &query.try_into()?)
        .await
        .map_err(KeystoneApiError::federation)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(IdentityProviderList { identity_providers })
}

/// Get single identity provider.
///
/// Shows details of the existing identity provider.
#[utoipa::path(
    get,
    path = "/{idp_id}",
    responses(
        (status = OK, description = "IDP object", body = IdentityProviderResponse),
        (status = 404, description = "IDP not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_get",
    level = "debug",
    skip(state, user_auth, policy),
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
        .get_identity_provider(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    policy
        .enforce(
            "identity/identity_provider_show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

/// Create the identity provider.
///
/// Create the identity provider with the specified properties.
///
/// It is expected that only admin user is able to create global identity providers.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "identity provider object", body = IdentityProviderResponse),
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_create",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
#[debug_handler]
async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<IdentityProviderCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/identity_provider_create",
            &user_auth,
            serde_json::to_value(&req.identity_provider)?,
            None,
        )
        .await?;

    let res = state
        .provider
        .get_federation_provider()
        .create_identity_provider(&state.db, req.into())
        .await
        .map_err(KeystoneApiError::federation)?;
    Ok((StatusCode::CREATED, res).into_response())
}

/// Update single identity provider.
///
/// Updates the existing identity provider.
#[utoipa::path(
    put,
    path = "/{idp_id}",
    params(),
    responses(
        (status = OK, description = "IDP object", body = IdentityProviderResponse),
        (status = 404, description = "IDP not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<IdentityProviderUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Fetch the current resource to pass current object into the policy evaluation
    let current = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state.db, &idp_id)
        .await?;

    policy
        .enforce(
            "identity/identity_provider_update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.identity_provider)?),
        )
        .await?;

    let res = state
        .provider
        .get_federation_provider()
        .update_identity_provider(&state.db, &idp_id, req.into())
        .await
        .map_err(KeystoneApiError::federation)?;
    Ok(res.into_response())
}

/// Delete Identity provider.
///
/// Deletes the existing identity provider.
///
/// It is expected that only admin user is allowed to delete the global identity provider
#[utoipa::path(
    delete,
    path = "/{idp_id}",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "identity provider not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_delete",
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
        .get_identity_provider(&state.db, &id)
        .await?;

    policy
        .enforce(
            "identity/identity_provider_delete",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;

    // TODO: decide what to do with the users provisioned using this IDP, mappings, ...

    if current.is_some() {
        state
            .provider
            .get_federation_provider()
            .delete_identity_provider(&state.db, &id)
            .await
            .map_err(KeystoneApiError::federation)?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "identity_provider".to_string(),
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
    use crate::federation::{
        MockFederationProvider, error::FederationProviderError, types as provider_types,
    };
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
            .expect_list_identity_providers()
            .withf(
                |_: &DatabaseConnection, _: &provider_types::IdentityProviderListParameters| true,
            )
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    default_mapping_name: Some("dummy".into()),
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
        let res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![IdentityProvider {
                id: "id".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                oidc_discovery_url: None,
                oidc_client_id: None,
                oidc_response_mode: None,
                oidc_response_types: None,
                jwt_validation_pubkeys: None,
                bound_issuer: None,
                default_mapping_name: Some("dummy".into()),
                provider_config: None
            }],
            res.identity_providers
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(
                |_: &DatabaseConnection, qp: &provider_types::IdentityProviderListParameters| {
                    provider_types::IdentityProviderListParameters {
                        name: Some("name".into()),
                        domain_id: Some("did".into()),
                    } == *qp
                },
            )
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
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
                    .uri("/?name=name&domain_id=did")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_forbidden() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(
                |_: &DatabaseConnection, _: &provider_types::IdentityProviderListParameters| true,
            )
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    default_mapping_name: Some("dummy".into()),
                    ..Default::default()
                }])
            });
        let state = get_mocked_state(federation_mock, false);

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_get() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    default_mapping_name: Some("dummy".into()),
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
        let res: IdentityProviderResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            IdentityProvider {
                id: "bar".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                oidc_discovery_url: None,
                oidc_client_id: None,
                oidc_response_mode: None,
                oidc_response_types: None,
                jwt_validation_pubkeys: None,
                bound_issuer: None,
                default_mapping_name: Some("dummy".into()),
                provider_config: None
            },
            res.identity_provider,
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_get_forbidden() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    default_mapping_name: Some("dummy".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(federation_mock, false);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_create() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_create_identity_provider()
            .withf(
                |_: &DatabaseConnection, req: &provider_types::IdentityProvider| req.name == "name",
            )
            .returning(|_, _| {
                Ok(provider_types::IdentityProvider {
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

        let req = IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreate {
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
        let res: IdentityProviderResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.identity_provider.name, req.identity_provider.name);
        assert_eq!(
            res.identity_provider.domain_id,
            req.identity_provider.domain_id
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_update() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "1")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });
        federation_mock
            .expect_update_identity_provider()
            .withf(
                |_: &DatabaseConnection,
                 id: &'_ str,
                 req: &provider_types::IdentityProviderUpdate| {
                    id == "1" && req.name == Some("name".to_string())
                },
            )
            .returning(|_, _, _| {
                Ok(provider_types::IdentityProvider {
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

        let req = IdentityProviderUpdateRequest {
            identity_provider: IdentityProviderUpdate {
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
        let _res: IdentityProviderResponse = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_delete() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        federation_mock
            .expect_get_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });
        federation_mock
            .expect_delete_identity_provider()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Err(FederationProviderError::IdentityProviderNotFound(
                    "foo".into(),
                ))
            });

        federation_mock
            .expect_delete_identity_provider()
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
