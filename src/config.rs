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

use config::{File, FileFormat};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    /// Global configuration options
    #[serde(rename = "DEFAULT")]
    pub default: Option<DefaultSection>,

    /// Database configuration
    pub database: DatabaseSection,

    /// Identity provider related configuration
    pub identity: Option<IdentitySection>,

    /// Security compliance
    #[serde(default)]
    pub security_compliance: SecurityComplianceSection,

    /// User options id to name mapping
    #[serde(default = "default_user_options_mapping")]
    pub user_options_id_name_mapping: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DefaultSection {}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DatabaseSection {
    pub connection: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct IdentitySection {
    #[serde(default = "default_identity_driver")]
    pub driver: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct SecurityComplianceSection {
    pub password_expires_days: Option<u64>,
}

fn default_identity_driver() -> String {
    "sql".into()
}

fn default_user_options_mapping() -> HashMap<String, String> {
    HashMap::from([
        (
            "1000".into(),
            "ignore_change_password_upon_first_use".into(),
        ),
        ("1001".into(), "ignore_password_expiry".into()),
        ("1002".into(), "ignore_lockout_failure_attempts".into()),
        ("1003".into(), "lock_password".into()),
    ])
}

impl Config {
    pub fn new(path: PathBuf) -> Self {
        let builder =
            config::Config::builder().add_source(File::from(path).format(FileFormat::Ini));

        builder.build().unwrap().try_deserialize().unwrap()
    }
}
