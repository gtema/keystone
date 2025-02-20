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
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::keystone::ServiceState;
use crate::provider::Provider;
use crate::token::{Token, TokenApi};

#[derive(Debug, Clone)]
pub struct Auth {
    pub token: Token,
}

pub async fn auth<P>(
    State(state): State<Arc<ServiceState<P>>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode>
where
    P: Provider,
{
    let auth_header = req
        .headers()
        .get("X-Auth-Token")
        .and_then(|header| header.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // insert the current user into a request extension so the handler can
    // extract it
    state
        .provider
        .get_token_provider()
        .validate_token(auth_header.to_string(), None)
        .await
        .map(|token| {
            req.extensions_mut().insert(Auth { token });
        })
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(next.run(req).await)
}
