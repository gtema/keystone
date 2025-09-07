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

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::Value;
use tracing::debug;
use webauthn_rs::prelude::*;

use crate::api::{
    error::{KeystoneApiError, WebauthnError},
    v4::auth::token::types::{Token as ApiToken, TokenResponse as ApiTokenResponse},
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::token::TokenApi;

/// Finish user passkey authentication.
///
/// Exchange the challenge signed with one of the users passkeys or security devices for the
/// unscoped Keystone API token.
#[utoipa::path(
    post,
    path = "/finish",
    operation_id = "/auth/passkey/finish:post",
    responses(
        (status = OK, description = "Authentication Token object", body = ApiTokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        )
        ),
    ),
    tags = ["passkey", "auth"]
)]
#[tracing::instrument(
    name = "api::user_passkey_login_finish",
    level = "debug",
    skip(state, req)
)]
pub(super) async fn finish(
    State(state): State<ServiceState>,
    Json(req): Json<Value>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let user_id = req
        .get("user_id")
        .and_then(|uid| uid.as_str())
        .ok_or_else(|| KeystoneApiError::Unauthorized)?
        .to_string();
    // TODO: Wrap all errors into the Unauthorized, but log the error
    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_passkey_authentication_state(&state.db, &user_id)
        .await?
    {
        // We explicitly try to deserealize the request data directly into the underlying
        // webauthn_rs type.
        let v: PublicKeyCredential = serde_json::from_value(req)?;
        match state.webauthn.finish_passkey_authentication(&v, &s) {
            Ok(_auth_result) => {
                // Here should the DB update happen (last_used, ...)
            }
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                return Err(WebauthnError::Unknown)?;
            }
        };
        state
            .provider
            .get_identity_provider()
            .delete_user_passkey_authentication_state(&state.db, &user_id)
            .await?;
    }
    let authed_info = AuthenticatedInfo::builder()
        .user_id(user_id.clone())
        .user(
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
                })??,
        )
        .methods(vec!["passkey".into()])
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    let token = state
        .provider
        .get_token_provider()
        .issue_token(authed_info, AuthzInfo::Unscoped)?;

    let api_token = ApiToken::from_provider_token(&state, &token).await?;
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}
