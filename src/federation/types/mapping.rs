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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct Mapping {
    /// Federation IDP mapping ID
    pub id: String,

    /// Mapping name
    pub name: String,

    #[builder(default)]
    pub domain_id: Option<String>,

    /// IDP ID
    pub idp_id: String,

    #[builder(default)]
    pub allowed_redirect_uris: Option<Vec<String>>,

    #[builder(default)]
    pub user_id_claim: String,

    #[builder(default)]
    pub user_name_claim: String,

    #[builder(default)]
    pub domain_id_claim: Option<String>,

    #[builder(default)]
    pub groups_claim: Option<String>,

    #[builder(default)]
    pub bound_audiences: Option<Vec<String>>,

    #[builder(default)]
    pub bound_subject: Option<String>,

    #[builder(default)]
    pub bound_claims: Option<Value>,

    #[builder(default)]
    pub oidc_scopes: Option<Vec<String>>,

    //#[builder(default)]
    //pub claim_mappings: Option<Value>,
    #[builder(default)]
    pub token_user_id: Option<String>,

    #[builder(default)]
    pub token_role_ids: Option<Vec<String>>,

    #[builder(default)]
    pub token_project_id: Option<String>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(into))]
pub struct MappingUpdate {
    /// Mapping name
    pub name: Option<String>,

    // TODO: on update must check that domain_id match
    #[builder(default)]
    pub idp_id: Option<String>,

    #[builder(default)]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub user_id_claim: Option<String>,

    #[builder(default)]
    pub user_name_claim: Option<String>,

    #[builder(default)]
    pub domain_id_claim: Option<String>,

    #[builder(default)]
    pub groups_claim: Option<Option<String>>,

    #[builder(default)]
    pub bound_audiences: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub bound_subject: Option<Option<String>>,

    #[builder(default)]
    pub bound_claims: Option<Value>,

    #[builder(default)]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub token_user_id: Option<Option<String>>,

    #[builder(default)]
    pub token_role_ids: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub token_project_id: Option<Option<String>>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct MappingListParameters {
    /// Filters the response by Mapping name.
    pub name: Option<String>,
    /// Filters the response by a domain_id ID.
    pub domain_id: Option<String>,
    /// Filters the response by IDP ID.
    pub idp_id: Option<String>,
}
