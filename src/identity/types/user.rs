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
use serde_json::Value;

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct User {
    /// The user ID.
    pub id: String,
    /// The user name. Must be unique within the owning domain.
    pub name: String,
    /// The ID of the domain.
    pub domain_id: String,
    /// If the user is enabled, this value is true. If the user is disabled, this value is false.
    pub enabled: bool,
    /// The resource description
    #[builder(default)]
    pub description: Option<String>,
    /// The ID of the default project for the user.
    #[builder(default)]
    pub default_project_id: Option<String>,
    /// Additional user properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The resource options for the user.
    #[builder(default)]
    pub password_expires_at: Option<DateTime<Utc>>,
    /// The resource options for the user.
    #[builder(default)]
    pub options: UserOptions,
    /// List of federated objects associated with a user. Each object in the list contains the idp_id and protocols. protocols is a list of objects, each of which contains protocol_id and unique_id of the protocol and user respectively.
    #[builder(default)]
    pub federated: Option<Vec<Federation>>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct UserCreate {
    pub id: String,
    /// The user name. Must be unique within the owning domain.
    pub name: String,
    /// The ID of the domain.
    pub domain_id: String,
    /// If the user is enabled, this value is true. If the user is disabled, this value is false.
    pub enabled: Option<bool>,
    /// The ID of the default project for the user.
    #[builder(default)]
    pub default_project_id: Option<String>,
    /// User password
    #[builder(default)]
    pub password: Option<String>,
    /// Additional user properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The resource options for the user.
    #[builder(default)]
    pub options: Option<UserOptions>,
    /// List of federated objects associated with a user. Each object in the list contains the idp_id and protocols. protocols is a list of objects, each of which contains protocol_id and unique_id of the protocol and user respectively.
    #[builder(default)]
    pub federated: Option<Vec<Federation>>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct UserUpdate {
    /// The user name. Must be unique within the owning domain.
    pub name: Option<String>,
    /// If the user is enabled, this value is true. If the user is disabled, this value is false.
    pub enabled: Option<bool>,
    /// The resource description
    #[builder(default)]
    pub description: Option<String>,
    /// The ID of the default project for the user.
    #[builder(default)]
    pub default_project_id: Option<String>,
    /// User password
    #[builder(default)]
    pub password: Option<String>,
    /// Additional user properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The resource options for the user.
    #[builder(default)]
    pub options: Option<UserOptions>,
    /// List of federated objects associated with a user. Each object in the list contains the idp_id and protocols. protocols is a list of objects, each of which contains protocol_id and unique_id of the protocol and user respectively.
    #[builder(default)]
    pub federated: Option<Vec<Federation>>,
}

impl UserBuilder {
    pub fn get_options(&self) -> Option<&UserOptions> {
        self.options.as_ref()
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct UserOptions {
    pub ignore_change_password_upon_first_use: Option<bool>,
    pub ignore_password_expiry: Option<bool>,
    pub ignore_lockout_failure_attempts: Option<bool>,
    pub lock_password: Option<bool>,
    pub ignore_user_inactivity: Option<bool>,
    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,
    pub multi_factor_auth_enabled: Option<bool>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct Federation {
    /// Identity provider ID
    pub idp_id: String,
    /// Protocols
    #[builder(default)]
    pub protocols: Vec<FederationProtocol>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct FederationProtocol {
    /// Federation protocol ID
    pub protocol_id: String,
    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user
    pub unique_id: String,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserListParameters {
    /// Filter users by the domain
    pub domain_id: Option<String>,
    /// Filter users by the name attribute
    pub name: Option<String>,
}
