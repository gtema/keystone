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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::Serialize;

use crate::api::error::TokenError;
use crate::token::Token as BackendToken;

#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize)]
pub struct Token {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

impl TryFrom<&BackendToken> for Token {
    type Error = TokenError;
    fn try_from(value: &BackendToken) -> Result<Self, Self::Error> {
        let mut token = TokenBuilder::default();
        if let BackendToken::Unscoped(data) = value {
            token.user_id(data.user_id.clone());
            token.methods(data.methods.clone());
            token.audit_ids(data.audit_ids.clone());
            token.expires_at(data.expires_at);
        }
        Ok(token.build()?)
    }
}
