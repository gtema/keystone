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

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct Assignment {
    /// The role ID.
    pub role_id: String,
    /// The actor id.
    pub actor_id: String,
    /// The target id.
    pub target_id: String,
    /// The assignment type
    pub r#type: AssignmentType,
    /// Inherited flag
    pub inherited: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum AssignmentType {
    GroupDomain,
    GroupProject,
    UserDomain,
    UserProject,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct RoleAssignmentListParameters {
    #[builder(default)]
    pub role_id: Option<String>,
    #[builder(default)]
    pub actor_id: Option<String>,
    #[builder(default)]
    pub target_id: Option<String>,
    #[builder(default)]
    pub r#type: Option<AssignmentType>,
}
