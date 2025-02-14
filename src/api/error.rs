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
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

use crate::identity::error::IdentityProviderError;

/// Keystone API operation errors
#[derive(Debug, Error)]
pub enum KeystoneApiError {
    #[error("conflict, resource already existing")]
    Conflict(String),

    #[error("could not find {resource}: {identifier}")]
    NotFound {
        resource: String,
        identifier: String,
    },

    #[error("missing authorization")]
    Unauthorized(String),

    #[error("internal server error")]
    InternalError(String),

    #[error(transparent)]
    IdentityError {
        #[from]
        source: IdentityProviderError,
    },
}

impl IntoResponse for KeystoneApiError {
    fn into_response(self) -> Response {
        match self {
            KeystoneApiError::Conflict(_) => (
                StatusCode::CONFLICT,
                Json(json!({"error": {"code": StatusCode::CONFLICT.as_u16(), "message": self.to_string()}})),
        ).into_response(),
            KeystoneApiError::NotFound{..} => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": {"code": StatusCode::NOT_FOUND.as_u16(), "message": self.to_string()}})),
            )
                .into_response(),
            KeystoneApiError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED,
                Json(json!({"error": {"code": StatusCode::UNAUTHORIZED.as_u16(), "message": self.to_string()}})),
                ).into_response()
            }
            KeystoneApiError::InternalError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": {"code": StatusCode::INTERNAL_SERVER_ERROR.as_u16(), "message": self.to_string()}})),
                ).into_response()
            }
            KeystoneApiError::IdentityError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": {"code": StatusCode::INTERNAL_SERVER_ERROR.as_u16(), "message": self.to_string()}})),
              ).into_response()
            }
        }
    }
}

impl KeystoneApiError {
    pub fn identity(source: IdentityProviderError) -> Self {
        match source {
            IdentityProviderError::UserNotFound(x) => Self::NotFound {
                resource: "user".into(),
                identifier: x,
            },
            IdentityProviderError::GroupNotFound(x) => Self::NotFound {
                resource: "group".into(),
                identifier: x,
            },
            _ => Self::IdentityError { source },
        }
    }
}
