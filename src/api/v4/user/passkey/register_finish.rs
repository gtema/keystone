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
use mockall_double::double;
use serde_json::Value;
use tracing::debug;
use webauthn_rs::prelude::*;

use crate::api::auth::Auth;
use crate::api::error::{KeystoneApiError, WebauthnError};
use crate::api::v4::user::types::passkey::UserPasskeyRegistrationFinishRequest;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Finish passkey registration for the user.
#[utoipa::path(
    post,
    path = "/register_finish",
    operation_id = "/user/passkey/register:finish",
    request_body = UserPasskeyRegistrationFinishRequest,
    params(
      ("user_id" = String, Path, description = "The ID of the user.")
    ),
    responses(
        (status = CREATED, description = "Passkey successfully registered"),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    tags = ["users", "passkey"]
)]
#[tracing::instrument(
    name = "api::user_passkey_register_finish",
    level = "debug",
    skip(state, policy, req),
    err(Debug)
)]
pub(super) async fn finish(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    mut policy: Policy,
    Json(req): Json<Value>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&state.db, &user_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: user_id.clone(),
            })
        })??;

    policy
        .enforce(
            "identity/user/passkey/register/finish",
            &user_auth,
            serde_json::to_value(&user)?,
            None,
        )
        .await?;

    if let Some(s) = state
        .provider
        .get_identity_provider()
        .get_user_passkey_registration_state(&state.db, &user_id)
        .await?
    {
        let v: RegisterPublicKeyCredential = serde_json::from_value(req)?;
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
    } else {
        return Err(WebauthnError::Unknown)?;
    }
    Ok((StatusCode::CREATED).into_response())
}
