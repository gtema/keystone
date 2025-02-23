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
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use std::sync::Arc;

use crate::keystone::ServiceState;
use crate::token::{Token, TokenApi};

#[derive(Debug, Clone)]
pub struct Auth(pub Token);

impl<S> FromRequestParts<S> for Auth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("X-Auth-Token")
            .and_then(|header| header.to_str().ok());

        let auth_header = if let Some(auth_header) = auth_header {
            auth_header
        } else {
            return Err((StatusCode::UNAUTHORIZED, "not authorized"));
        };

        let state = Arc::from_ref(state);

        Ok(Self(
            state
                .provider
                .get_token_provider()
                .validate_token(auth_header.to_string(), None)
                .await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "not authorized"))?,
        ))
    }
}
