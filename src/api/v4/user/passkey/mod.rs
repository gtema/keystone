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
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::*;

use crate::api::{
    error::{KeystoneApiError, WebauthnError},
    v3::auth::token::types::Token as ApiToken,
};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::token::TokenApi;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(register_start))
        .routes(routes!(register_finish))
        .routes(routes!(login_start))
        .routes(routes!(login_finish))
}

/// Start passkey registration
#[utoipa::path(
    post,
    path = "/register_start",
    description = "Start passkey registration",
    responses(),
    tag = "passkey"
)]
#[tracing::instrument(
    name = "api::user_passkey_register_start",
    level = "debug",
    skip(state)
)]
async fn register_start(
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_identity_provider()
        .delete_user_passkey_registration_state(&state.db, &user_id)
        .await?;
    // TODO: user names
    let res = match state.webauthn.start_passkey_registration(
        Uuid::parse_str(&user_id)?,
        "foo",
        "foo",
        None,
    ) {
        Ok((ccr, reg_state)) => {
            state
                .provider
                .get_identity_provider()
                .save_user_passkey_registration_state(&state.db, &user_id, reg_state)
                .await?;
            Json(ccr)
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown)?;
        }
    };

    Ok(res)
}

/// Finish passkey registration
#[utoipa::path(
    post,
    path = "/register_finish",
    description = "Finish passkey registration",
    responses(),
    tag = "passkey"
)]
#[tracing::instrument(
    name = "api::user_passkey_register_finish",
    level = "debug",
    skip(state, reg)
)]
async fn register_finish(
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(reg): Json<Value>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_passkey_registration_state(&state.db, &user_id)
        .await?
    {
        let v: RegisterPublicKeyCredential = serde_json::from_value(reg)?;
        match state.webauthn.finish_passkey_registration(&v, &s) {
            Ok(sk) => {
                state
                    .provider
                    .get_identity_provider()
                    .create_user_passkey(&state.db, &user_id, sk)
                    .await?;
            }
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                return Err(WebauthnError::Unknown)?;
            }
        };
        state
            .provider
            .get_identity_provider()
            .delete_user_passkey_registration_state(&state.db, &user_id)
            .await?;
    }
    Ok((StatusCode::OK).into_response())
}

/// Start passkey authentication
#[utoipa::path(
    post,
    path = "/login_start",
    description = "Start passkey authentication",
    responses(),
    tag = "passkey"
)]
#[tracing::instrument(
    name = "api::user_passkey_authentication_start",
    level = "debug",
    skip(state)
)]
async fn login_start(
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .provider
        .get_identity_provider()
        .delete_user_passkey_authentication_state(&state.db, &user_id)
        .await?;
    let allow_credentials: Vec<Passkey> = state
        .provider
        .get_identity_provider()
        .list_user_passkeys(&state.db, &user_id)
        .await?
        .into_iter()
        .collect();
    let res = match state
        .webauthn
        .start_passkey_authentication(allow_credentials.as_ref())
    {
        Ok((rcr, auth_state)) => {
            state
                .provider
                .get_identity_provider()
                .save_user_passkey_authentication_state(&state.db, &user_id, auth_state)
                .await?;
            Json(rcr)
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown)?;
        }
    };

    Ok(res)
}

/// Finish passkey auth
#[utoipa::path(
    post,
    path = "/login_finish",
    description = "Finish passkey login",
    responses(),
    tag = "passkey"
)]
#[tracing::instrument(
    name = "api::user_passkey_login_finish",
    level = "debug",
    skip(state, reg)
)]
async fn login_finish(
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(reg): Json<Value>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_passkey_authentication_state(&state.db, &user_id)
        .await?
    {
        let v: PublicKeyCredential = serde_json::from_value(reg)?;
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
