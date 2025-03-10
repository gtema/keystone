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

use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::token::TokenApi;
use types::{Token as ApiResponseToken, TokenResponse};

mod common;
pub mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(show))
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
#[tracing::instrument(name = "api::token_get", level = "debug", skip(state))]
async fn show(
    Auth(user_auth): Auth,
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

    let response_token = ApiResponseToken::from_provider_token(&token, &state).await?;

    Ok(TokenResponse {
        token: response_token,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::auth::token::types::TokenResponse;
    use crate::assignment::MockAssignmentProvider;
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::User};
    use crate::keystone::Service;
    use crate::provider::ProviderBuilder;
    use crate::resource::{MockResourceProvider, types::Domain};
    use crate::tests::api::get_mocked_state_unauthed;
    use crate::token::*;

    #[tokio::test]
    async fn test_get() {
        let db = DatabaseConnection::Disconnected;
        let config = Config::default();
        let assignment_mock = MockAssignmentProvider::default();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id: &'_ str| {
            Ok(Some(User {
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
}
