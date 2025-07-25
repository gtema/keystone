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
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    /// Global configuration options
    #[serde(rename = "DEFAULT")]
    pub default: Option<DefaultSection>,
    ///
    /// Assignments (roles) related configuration
    #[serde(default)]
    pub assignment: AssignmentSection,

    /// Auth
    #[serde(default)]
    pub auth: AuthSection,

    /// Catalog
    #[serde(default)]
    pub catalog: CatalogSection,

    #[serde(default)]
    pub federation: FederationSection,

    /// Fernet tokens
    #[serde(default)]
    pub fernet_tokens: FernetTokenSection,

    /// Database configuration
    #[serde(default)]
    pub database: DatabaseSection,

    /// Identity provider related configuration
    #[serde(default)]
    pub identity: IdentitySection,

    /// API policy enforcement
    #[serde(default)]
    pub api_policy: PolicySection,

    /// Resource provider related configuration
    #[serde(default)]
    pub resource: ResourceSection,

    /// Security compliance
    #[serde(default)]
    pub security_compliance: SecurityComplianceSection,

    /// Token
    #[serde(default)]
    pub token: TokenSection,

    /// User options id to name mapping
    #[serde(default = "default_user_options_mapping")]
    pub user_options_id_name_mapping: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct DefaultSection {
    /// Debug logging
    pub debug: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AuthSection {
    #[serde(deserialize_with = "csv")]
    pub methods: Vec<String>,
}

pub fn csv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(String::deserialize(deserializer)?
        .split(',')
        .map(Into::into)
        .collect())
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FernetTokenSection {
    pub key_repository: PathBuf,
    pub max_active_keys: usize,
}

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

/// The configuration options for the API policy enforcement.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PolicySection {
    /// Whether the policy enforcement should be enforced or not.
    pub enable: bool,

    /// OpenPolicyAgent instance url to use for evaluating the policy.
    pub opa_base_url: Option<Url>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct AssignmentSection {
    pub driver: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct CatalogSection {
    pub driver: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FederationSection {
    pub driver: String,
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
pub struct ResourceSection {
    pub driver: String,
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

#[derive(Debug, Default, Deserialize, Clone)]
pub struct TokenSection {
    #[serde(default)]
    pub provider: TokenProvider,
    /// The amount of time that a token should remain valid (in seconds). Drastically reducing this
    /// value may break "long-running" operations that involve multiple services to coordinate
    /// together, and will force users to authenticate with keystone more frequently. Drastically
    /// increasing this value will increase the number of tokens that will be simultaneously valid.
    /// Keystone tokens are also bearer tokens, so a shorter duration will also reduce the
    /// potential security impact of a compromised token.
    #[serde(default)]
    pub expiration: usize,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub enum TokenProvider {
    #[default]
    #[serde(rename = "fernet")]
    Fernet,
}

impl Config {
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        let mut builder = config::Config::builder();

        builder = builder
            .set_default("api_policy.enable", "true")?
            .set_default("api_policy.opa_base_url", "http://localhost:8181")?
            .set_default("identity.max_password_length", "4096")?
            .set_default("fernet_tokens.key_repository", "/etc/keystone/fernet-keys/")?
            .set_default("fernet_tokens.max_active_keys", "3")?
            .set_default("assignment.driver", "sql")?
            .set_default("catalog.driver", "sql")?
            .set_default("federation.driver", "sql")?
            .set_default("resource.driver", "sql")?
            .set_default("token.expiration", "3600")?;
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
        };
        assert_eq!("mysql://u:p@h", sot.get_connection());
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection());
    }
}
