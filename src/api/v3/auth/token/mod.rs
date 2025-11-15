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
    extract::{Query, State},
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::{json, to_value};
use tracing::error;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::types::Scope;
use crate::api::v3::auth::token::types::{
    AuthRequest, CreateTokenParameters, Token as ApiResponseToken, TokenResponse,
    ValidateTokenParameters,
};
use crate::api::{
    Catalog,
    auth::Auth,
    common::{find_project_from_scope, get_domain},
    error::KeystoneApiError,
};
use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::catalog::CatalogApi;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::TokenApi;

mod common;
pub mod types;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(show, post))
}

/// Authenticate the user ignoring any scope information. It is important not to expose any
/// hints that user, project, domain, etc might exist before we have authenticated them by
/// taking different amount of time in case of certain validations.
async fn authenticate_request(
    state: &ServiceState,
    req: &AuthRequest,
) -> Result<AuthenticatedInfo, KeystoneApiError> {
    let mut authenticated_info: Option<AuthenticatedInfo> = None;
    for method in req.auth.identity.methods.iter() {
        if method == "password" {
            if let Some(password_auth) = &req.auth.identity.password {
                let req = password_auth.user.clone().try_into()?;
                authenticated_info = Some(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_password(state, req)
                        .await?,
                );
            }
        } else if method == "token"
            && let Some(token) = &req.auth.identity.token
        {
            let mut authz = state
                .provider
                .get_token_provider()
                .authenticate_by_token(state, &token.id, Some(false), None)
                .await?;
            // Resolve the user
            authz.user = Some(
                state
                    .provider
                    .get_identity_provider()
                    .get_user(state, &authz.user_id)
                    .await
                    .map(|x| {
                        x.ok_or_else(|| KeystoneApiError::NotFound {
                            resource: "user".into(),
                            identifier: authz.user_id.clone(),
                        })
                    })??,
            );
            authenticated_info = Some(authz);

            {}
        }
    }
    authenticated_info
        .ok_or(KeystoneApiError::Unauthorized)
        .and_then(|authn| {
            authn.validate()?;
            Ok(authn)
        })
}

/// Build the AuthZ information from the request
///
/// # Arguments
///
/// * `state` - The service state
/// * `req` - The Request
///
/// # Result
///
/// * `Ok(AuthzInfo)` - The AuthZ information
/// * `Err(KeystoneApiError)` - The error
async fn get_authz_info(
    state: &ServiceState,
    req: &AuthRequest,
) -> Result<AuthzInfo, KeystoneApiError> {
    let authz_info = match &req.auth.scope {
        Some(Scope::Project(scope)) => {
            if let Some(project) = find_project_from_scope(state, scope).await? {
                AuthzInfo::Project(project)
            } else {
                return Err(KeystoneApiError::Unauthorized);
            }
        }
        Some(Scope::Domain(scope)) => {
            if let Ok(domain) = get_domain(state, scope.id.as_ref(), scope.name.as_ref()).await {
                AuthzInfo::Domain(domain)
            } else {
                return Err(KeystoneApiError::Unauthorized);
            }
        }
        Some(Scope::System(_scope)) => {
            todo!()
        }
        None => AuthzInfo::Unscoped,
    };
    authz_info.validate()?;
    Ok(authz_info)
}

/// Authenticate user issuing a new token.
#[utoipa::path(
    post,
    path = "/",
    description = "Issue token",
    params(CreateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(name = "api::token_post", level = "debug", skip(state, req))]
async fn post(
    Query(query): Query<CreateTokenParameters>,
    State(state): State<ServiceState>,
    Json(req): Json<AuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let authed_info = authenticate_request(&state, &req).await?;
    let authz_info = get_authz_info(&state, &req).await?;
    if let Some(restriction_id) = &authed_info.token_restriction_id {
        let restriction = state
            .provider
            .get_token_provider()
            .get_token_restriction(&state, restriction_id, true)
            .await?
            .ok_or(KeystoneApiError::InternalError(
                "token restriction {restriction_id} not found".to_string(),
            ))?;
        if !restriction.allow_rescope && req.auth.scope.is_some() {
            return Err(KeystoneApiError::AuthenticationRescopeForbidden);
        }
    }

    let mut token =
        state
            .provider
            .get_token_provider()
            .issue_token(authed_info, authz_info, None)?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await?;

    let mut api_token = TokenResponse {
        token: ApiResponseToken::from_provider_token(&state, &token).await?,
    };
    if !query.nocatalog.is_some_and(|x| x) {
        let catalog: Catalog = state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into();
        api_token.token.catalog = Some(catalog);
    }
    return Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response());
}

/// Validate token
#[utoipa::path(
    get,
    path = "/",
    description = "Validate token",
    params(ValidateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(
    name = "api::v3::token_get",
    level = "debug",
    skip(state, headers, user_auth, policy)
)]
async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<ValidateTokenParameters>,
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let subject_token: String = headers
        .get("X-Subject-Token")
        .ok_or(KeystoneApiError::SubjectTokenMissing)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .to_string();

    // Default behavior is to return 404 for expired tokens. It makes sense to log internally the
    // error before mapping it.
    let mut token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &subject_token, query.allow_expired, None)
        .await
        .inspect_err(|e| error!("{:?}", e.to_string()))
        .map_err(|_| KeystoneApiError::NotFound {
            resource: "token".into(),
            identifier: String::new(),
        })?;

    policy
        .enforce(
            "identity/auth/token/show",
            &user_auth,
            to_value(json!({"token": &token}))?,
            None,
        )
        .await?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await
        .map_err(|_| KeystoneApiError::Forbidden)?;

    let mut response_token = ApiResponseToken::from_provider_token(&state, &token).await?;

    if !query.nocatalog.is_some_and(|x| x) {
        let catalog: Catalog = state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into();
        response_token.catalog = Some(catalog);
    }

    Ok(TokenResponse {
        token: response_token,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::openapi_router;
    use crate::api::v3::auth::token::types::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::auth::AuthenticatedInfo;
    use crate::catalog::MockCatalogProvider;
    use crate::config::Config;
    use crate::identity::{
        MockIdentityProvider,
        types::{UserPasswordAuthRequest, UserResponse},
    };
    use crate::keystone::Service;
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::resource::{
        MockResourceProvider,
        types::{Domain, Project},
    };
    use crate::tests::api::get_mocked_state_unauthed;
    use crate::token::{
        MockTokenProvider, ProjectScopePayload, Token as ProviderToken, TokenProviderError,
        UnscopedPayload,
    };

    use super::*;

    fn get_policy_factory_mock() -> MockPolicyFactory {
        let mut policy_factory_mock = MockPolicyFactory::default();
        policy_factory_mock.expect_instantiate().returning(|| {
            let mut policy_mock = MockPolicy::default();
            policy_mock
                .expect_enforce()
                .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
            Ok(policy_mock)
        });
        policy_factory_mock
    }

    #[tokio::test]
    async fn test_authenticate_request_password() {
        let config = Config::default();
        let auth_info = AuthenticatedInfo::builder()
            .user_id("uid")
            .user(UserResponse {
                id: "uid".to_string(),
                domain_id: "udid".into(),
                enabled: true,
                ..Default::default()
            })
            .build()
            .unwrap();
        let auth_clone = auth_info.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password == "pwd"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        assert_eq!(
            auth_info,
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["password".to_string()],
                            password: Some(PasswordAuth {
                                user: UserPassword {
                                    id: Some("uid".to_string()),
                                    password: "pwd".to_string(),
                                    name: Some("uname".to_string()),
                                    ..Default::default()
                                },
                            }),
                            token: None,
                        },
                        scope: None,
                    },
                }
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_token() {
        let config = Config::default();

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_authenticate_by_token()
            .withf(
                |_, id: &'_ str, allow_expired: &Option<bool>, window: &Option<i64>| {
                    id == "fake_token" && *allow_expired == Some(false) && window.is_none()
                },
            )
            .returning(|_, _, _, _| {
                Ok(AuthenticatedInfo::builder().user_id("uid").build().unwrap())
            });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "uid")
            .returning(|_, id: &'_ str| {
                Ok(Some(UserResponse {
                    id: id.to_string(),
                    domain_id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        assert_eq!(
            AuthenticatedInfo::builder()
                .user_id("uid")
                .user(UserResponse {
                    id: "uid".to_string(),
                    domain_id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                })
                .build()
                .unwrap(),
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["token".to_string()],
                            password: None,
                            token: Some(TokenAuth {
                                id: "fake_token".to_string()
                            }),
                        },
                        scope: None,
                    },
                }
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_unsupported() {
        let config = Config::default();

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let rsp = authenticate_request(
            &state,
            &AuthRequest {
                auth: AuthRequestInner {
                    identity: Identity {
                        methods: vec!["fake".to_string()],
                        password: None,
                        token: None,
                    },
                    scope: None,
                },
            },
        )
        .await;
        if let KeystoneApiError::Unauthorized = rsp.unwrap_err() {
        } else {
            panic!("Should receive Unauthorized");
        }
    }

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id: &'_ str| {
            Ok(Some(UserResponse {
                id: id.to_string(),
                domain_id: "user_domain_id".into(),
                ..Default::default()
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _, _| {
            Ok(ProviderToken::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_populate_role_assignments()
            .returning(|_, _| Ok(()));
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .catalog(catalog_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .header("x-subject-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: TokenResponse = serde_json::from_slice(&body).unwrap();

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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_allow_expired() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id: &'_ str| {
            Ok(Some(UserResponse {
                id: id.to_string(),
                domain_id: "user_domain_id".into(),
                ..Default::default()
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _| token == "foo")
            .returning(|_, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, allow_expired: &Option<bool>, _| {
                token == "bar" && *allow_expired == Some(true)
            })
            .returning(|_, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_populate_role_assignments()
            .returning(|_, _| Ok(()));
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .catalog(catalog_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?allow_expired=true")
                    .header("x-auth-token", "foo")
                    .header("x-subject-token", "bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_expired() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _| token == "foo")
            .returning(|_, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_expand_token_information()
            .withf(|_, token: &ProviderToken| token.user_id() == "bar")
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "foo".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(|_, _, _, _| Err(TokenProviderError::Expired));

        let provider = Provider::mocked_builder()
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_unauth() {
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
    #[traced_test]
    async fn test_post() {
        let config = Config::default();
        let project = Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let user_domain = Domain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };
        let project_domain = Domain {
            id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let mut assignment_mock = MockAssignmentProvider::default();
        let mut catalog_mock = MockCatalogProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password == "pass"
                    && req.name == Some("uname".to_string())
            })
            .returning(|_, _| {
                Ok(AuthenticatedInfo::builder()
                    .user_id("uid")
                    .user(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "udid".into(),
                        enabled: true,
                        ..Default::default()
                    })
                    .build()
                    .unwrap())
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| Ok(Some(project.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(move |_, _| Ok(Some(user_domain.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(move |_, _| Ok(Some(project_domain.clone())));
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_issue_token().returning(|_, _, _| {
            Ok(ProviderToken::ProjectScope(ProjectScopePayload {
                user_id: "bar".into(),
                methods: Vec::from(["password".to_string()]),
                user: Some(UserResponse {
                    id: "uid".to_string(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                }),
                project_id: "pid".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_populate_role_assignments()
            .returning(|_, _| Ok(()));
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::ProjectScope(ProjectScopePayload {
                    user_id: "bar".into(),
                    methods: Vec::from(["password".to_string()]),
                    user: Some(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "user_domain_id".into(),
                        ..Default::default()
                    }),
                    project_id: "pid".into(),
                    project: Some(Project {
                        id: "pid".into(),
                        domain_id: "pdid".into(),
                        enabled: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .assignment(assignment_mock)
            .catalog(catalog_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(vec!["password"], res.token.methods);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_post_project_disabled() {
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| {
                Ok(AuthenticatedInfo::builder()
                    .user_id("uid")
                    .user(UserResponse {
                        id: "uid".to_string(),
                        domain_id: "udid".into(),
                        enabled: true,
                        ..Default::default()
                    })
                    .build()
                    .unwrap())
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| {
                Ok(Some(Project {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: false,
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
