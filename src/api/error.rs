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
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

use crate::api::v3::federation::error::OidcError;

use crate::assignment::error::AssignmentProviderError;
use crate::catalog::error::CatalogProviderError;
use crate::federation::error::FederationProviderError;
use crate::identity::error::IdentityProviderError;
use crate::resource::error::ResourceProviderError;
use crate::token::error::TokenProviderError;

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

    #[error("The request you have made requires authentication.")]
    Unauthorized,

    #[error("You are not authorized to perform the requested action.")]
    Forbidden,

    #[error("missing x-subject-token header")]
    SubjectTokenMissing,

    #[error("invalid header header")]
    InvalidHeader,

    #[error("invalid token")]
    InvalidToken,

    #[error("error building token data: {}", source)]
    Token {
        #[from]
        source: TokenError,
    },

    #[error("internal server error: {0}")]
    InternalError(String),

    #[error(transparent)]
    AssignmentError {
        #[from]
        source: AssignmentProviderError,
    },

    #[error(transparent)]
    CatalogError {
        #[from]
        source: CatalogProviderError,
    },

    #[error(transparent)]
    Federation {
        #[from]
        source: FederationProviderError,
    },

    #[error(transparent)]
    Oidc {
        #[from]
        source: OidcError,
    },

    #[error(transparent)]
    IdentityError {
        #[from]
        source: IdentityProviderError,
    },

    #[error(transparent)]
    ResourceError {
        #[from]
        source: ResourceProviderError,
    },

    #[error(transparent)]
    TokenError {
        #[from]
        source: TokenProviderError,
    },

    #[error(transparent)]
    WebAuthN {
        #[from]
        source: WebauthnError,
    },

    #[error(transparent)]
    Uuid {
        #[from]
        source: uuid::Error,
    },

    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("domain id or name must be present")]
    DomainIdOrName,

    #[error("project id or name must be present")]
    ProjectIdOrName,

    #[error("project domain must be present")]
    ProjectDomain,

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    /// Others.
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl IntoResponse for KeystoneApiError {
    fn into_response(self) -> Response {
        error!("Error happened during request processing: {:#?}", self);
        //tracing::debug!("stacktrace: {}", self.backtrace());
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
            KeystoneApiError::Unauthorized => {
                (StatusCode::UNAUTHORIZED,
                Json(json!({"error": {"code": StatusCode::UNAUTHORIZED.as_u16(), "message": self.to_string()}})),
                ).into_response()
            }
            KeystoneApiError::InternalError(_) | KeystoneApiError::IdentityError { .. } | KeystoneApiError::ResourceError { .. } | KeystoneApiError::AssignmentError { .. } | KeystoneApiError::TokenError{..} | KeystoneApiError::Federation {..} | KeystoneApiError::Oidc{..} | KeystoneApiError::Other(..) => {
                (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": {"code": StatusCode::INTERNAL_SERVER_ERROR.as_u16(), "message": self.to_string()}})),
              ).into_response()
            }
            _ =>  {
            // KeystoneApiError::SubjectTokenMissing | KeystoneApiError::InvalidHeader | KeystoneApiError::InvalidToken | KeystoneApiError::Token{..} | KeystoneApiError::WebAuthN{..} | KeystoneApiError::Uuid {..} | KeystoneApiError::Serde {..} | KeystoneApiError::DomainIdOrName | KeystoneApiError::ProjectIdOrName | KeystoneApiError::ProjectDomain =>
                (StatusCode::BAD_REQUEST,
                Json(json!({"error": {"code": StatusCode::BAD_REQUEST.as_u16(), "message": self.to_string()}})),
              ).into_response()
            }
        }
    }
}

impl KeystoneApiError {
    pub fn assignment(source: AssignmentProviderError) -> Self {
        match source {
            AssignmentProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            _ => Self::AssignmentError { source },
        }
    }
    pub fn federation(source: FederationProviderError) -> Self {
        match source {
            FederationProviderError::IdentityProviderNotFound(x) => Self::NotFound {
                resource: "identity provider".into(),
                identifier: x,
            },
            FederationProviderError::MappingNotFound(x) => Self::NotFound {
                resource: "mapping provider".into(),
                identifier: x,
            },
            _ => Self::Federation { source },
        }
    }
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
    pub fn resource(source: ResourceProviderError) -> Self {
        match source {
            ResourceProviderError::DomainNotFound(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            _ => Self::ResourceError { source },
        }
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("error building token data: {}", source)]
    Builder {
        #[from]
        source: crate::api::v3::auth::token::types::TokenBuilderError,
    },

    #[error("error building token user data: {}", source)]
    UserBuilder {
        #[from]
        source: crate::api::v3::auth::token::types::UserBuilderError,
    },

    #[error("error building token user data: {}", source)]
    ProjectBuilder {
        #[from]
        source: crate::api::types::ProjectBuilderError,
    },

    #[error(transparent)]
    UserPasswordAuthBuilder {
        #[from]
        source: crate::identity::types::user::UserPasswordAuthRequestBuilderError,
    },
    #[error(transparent)]
    DomainBuilder {
        #[from]
        source: crate::identity::types::user::DomainBuilderError,
    },
}

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
}
impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            WebauthnError::CorruptSession => "Corrupt Session",
            WebauthnError::UserNotFound => "User Not Found",
            WebauthnError::Unknown => "Unknown Error",
            WebauthnError::UserHasNoCredentials => "User Has No Credentials",
        };

        // its often easiest to implement `IntoResponse` by calling other implementations
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
