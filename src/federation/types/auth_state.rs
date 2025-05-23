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
use serde::{Deserialize, Serialize};

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct AuthState {
    /// IDP ID
    pub idp_id: String,

    /// Mapping ID
    pub mapping_id: String,

    /// Auth state (Primary key, CSRF)
    pub state: String,

    /// Nonce
    pub nonce: String,

    /// Requested redirect uri
    pub redirect_uri: String,

    /// PKCE verifier value
    pub pkce_verifier: String,

    /// Timestamp when the auth was initiated
    #[builder(default)]
    pub started_at: DateTime<Utc>,

    /// Requested scope
    #[builder(default)]
    pub scope: Option<Scope>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Project(String),
    Domain(String),
    System(String),
}
