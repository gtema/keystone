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
use eyre::Report;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    /// Global configuration options
    #[serde(rename = "DEFAULT")]
    pub default: Option<DefaultSection>,

    /// Database configuration
    #[serde(default)]
    pub database: DatabaseSection,

    /// Identity provider related configuration
    #[serde(default)]
    pub identity: IdentitySection,

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

impl DatabaseSection {
    pub fn get_connection(&self) -> String {
        if self.connection.contains("+") {
            let re = Regex::new(r"(?<type>\w+)\+(\w+)://").unwrap();
            return re.replace(&self.connection, "${type}://").to_string();
        }
        self.connection.clone()
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct IdentitySection {
    #[serde(default = "default_identity_driver")]
    pub driver: String,

    #[serde(default)]
    pub password_hashing_algorithm: PasswordHashingAlgo,
    pub max_password_length: usize,
    pub password_hash_rounds: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub enum PasswordHashingAlgo {
    #[default]
    Bcrypt,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct SecurityComplianceSection {
    pub password_expires_days: Option<u64>,
    pub disable_user_account_days_inactive: Option<i16>,
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
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        let mut builder = config::Config::builder();

        builder = builder.set_default("identity.max_password_length", "4096")?;
        if std::path::Path::new(&path).is_file() {
            builder = builder.add_source(File::from(path).format(FileFormat::Ini));
        }

        Ok(builder.build()?.try_deserialize()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_connection() {
        let sot = DatabaseSection {
            connection: "mysql://u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p@h", sot.get_connection());
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p@h", sot.get_connection());
    }
}
