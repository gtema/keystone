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

use axum::{Json, extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::api::{auth::Auth, common::get_domain, error::KeystoneApiError};
use crate::identity::IdentityApi;
use crate::identity::types::UserResponse;
use crate::keystone::ServiceState;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
use crate::token::TokenApi;
use types::{AuthRequest, Scope, Token as ApiResponseToken, TokenResponse};

mod common;
pub mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(show, post))
}

/// Authenticate user issuing a new token
#[utoipa::path(
    post,
    path = "/",
    description = "Issue token",
    params(),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(name = "api::token_post", level = "debug", skip(state, req))]
async fn post(
    State(state): State<ServiceState>,
    Json(req): Json<AuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let mut methods: Vec<String> = Vec::new();
    let mut user: Option<UserResponse> = None;
    let mut project: Option<Project> = None;
    let mut domain: Option<Domain> = None;

    match req.auth.scope {
        Some(Scope::Project(scope)) => {
            project = if let Some(pid) = &scope.id {
                state
                    .provider
                    .get_resource_provider()
                    .get_project(&state.db, pid)
                    .await?
            } else if let Some(name) = &scope.name {
                if let Some(domain) = scope.domain {
                    let domain_id = match domain.id {
                        Some(id) => id.clone(),
                        None => {
                            state
                                .provider
                                .get_resource_provider()
                                .find_domain_by_name(
                                    &state.db,
                                    &domain
                                        .name
                                        .clone()
                                        .ok_or(KeystoneApiError::DomainIdOrName)?,
                                )
                                .await?
                                .ok_or(KeystoneApiError::NotFound {
                                    resource: "domain".to_string(),
                                    identifier: domain
                                        .name
                                        .clone()
                                        .ok_or(KeystoneApiError::DomainIdOrName)?,
                                })?
                                .id
                        }
                    };
                    state
                        .provider
                        .get_resource_provider()
                        .get_project_by_name(&state.db, name, &domain_id)
                        .await?
                } else {
                    return Err(KeystoneApiError::ProjectDomain);
                }
            } else {
                return Err(KeystoneApiError::ProjectIdOrName);
            };
            if !project.as_ref().is_some_and(|target| target.enabled) {
                return Err(KeystoneApiError::Unauthorized);
            }
        }
        Some(Scope::Domain(scope)) => {
            domain = Some(get_domain(&state, scope.id.as_ref(), scope.name.as_ref()).await?);
            if !domain.as_ref().is_some_and(|target| target.enabled) {
                return Err(KeystoneApiError::Unauthorized);
            }
        }
        None => {}
    }

    for method in req.auth.identity.methods.iter() {
        if method == "password" {
            if let Some(password_auth) = &req.auth.identity.password {
                let req = password_auth.user.clone().try_into()?;
                user = Some(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_password(&state.db, &state.provider, req)
                        .await?,
                );
                methods.push(method.clone());
            }
        }
    }

    if let Some(authed_user) = &user {
        let token = state.provider.get_token_provider().issue_token(
            authed_user.id.clone(),
            methods,
            Vec::<String>::from([URL_SAFE
                .encode(Uuid::new_v4().as_bytes())
                .trim_end_matches('=')
                .to_string()]),
            project.as_ref(),
            domain.as_ref(),
        )?;

        let api_token = TokenResponse {
            token: ApiResponseToken::from_user_auth(
                &state,
                &token,
                authed_user,
                project.as_ref(),
                domain.as_ref(),
            )
            .await?,
        };
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

    return Err(KeystoneApiError::Unauthorized);
}

/// Validate token
#[utoipa::path(
    get,
    path = "/",
    description = "Validate token",
    params(),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(
    name = "api::token_get",
    level = "debug",
    skip(state, headers, _user_auth)
)]
async fn show(
    Auth(_user_auth): Auth,
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let subject_token: String = headers
        .get("X-Subject-Token")
        .ok_or(KeystoneApiError::SubjectTokenMissing)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .to_string();

    let token = state
        .provider
        .get_token_provider()
        .validate_token(&subject_token, None)
        .await
        .map_err(|_| KeystoneApiError::InvalidToken)?;

    let response_token = ApiResponseToken::from_provider_token(&state, &token).await?;

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

    use super::openapi_router;
    use crate::api::v3::auth::token::types::TokenResponse;
    use crate::assignment::MockAssignmentProvider;
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::UserResponse};
    use crate::keystone::Service;
    use crate::provider::ProviderBuilder;
    use crate::resource::{
        MockResourceProvider,
        types::{Domain, Project},
    };
    use crate::tests::api::get_mocked_state_unauthed;
    use crate::token::*;

    #[tokio::test]
    async fn test_get() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let assignment_mock = MockAssignmentProvider::default();
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
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _| {
            Ok(Token::Unscoped(UnscopedToken {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });

        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(Service::new(config, db, provider).unwrap());

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
    async fn test_post() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _, _| Ok(Vec::new()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _, _| {
                Ok(UserResponse {
                    id: "uid".to_string(),
                    domain_id: "user_domain_id".into(),
                    ..Default::default()
                })
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "pid")
            .returning(|_, _| {
                Ok(Some(Project {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "pdid")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_issue_token().returning(|_, _, _, _, _| {
            Ok(Token::ProjectScope(ProjectScopeToken {
                user_id: "bar".into(),
                methods: Vec::from(["password".to_string()]),
                ..Default::default()
            }))
        });

        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));

        let provider = ProviderBuilder::default()
            .config(config.clone())
            .assignment(assignment_mock)
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(Service::new(config, db, provider).unwrap());

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
}
