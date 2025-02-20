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

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::{DateTime, Utc};
use fernet::{Fernet, MultiFernet};
use rmp::{decode::*, Marker};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::io::Read;
use uuid::Uuid;

use crate::config::Config;
use crate::token::{
    fernet_utils::FernetUtils,
    types::{Token, TokenBackend},
    TokenProviderError,
};

#[derive(Default, Clone)]
pub struct FernetTokenProvider {
    config: Config,
    utils: FernetUtils,
    fernet: Option<MultiFernet>,
    auth_map: BTreeMap<usize, String>,
}

impl fmt::Debug for FernetTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FernetTokenProvider").finish()
    }
}

/// Read the payload version
fn read_payload_token_type(rd: &mut &[u8]) -> Result<u8, TokenProviderError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixPos(dt) => Ok(dt),
        Marker::U8 => Ok(read_u8(rd)?),
        _ => Err(TokenProviderError::InvalidToken),
    }
}

/// Read binary data from the payload
fn read_bin_data<R: Read>(len: u32, rd: &mut R) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(len.min(1 << 16) as usize);
    let bytes_read = rd.take(u64::from(len)).read_to_end(&mut buf)?;
    if bytes_read != len as usize {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(buf)
}

/// Read string data
fn read_str_data<R: Read>(len: u32, rd: &mut R) -> Result<String, io::Error> {
    Ok(String::from_utf8_lossy(&read_bin_data(len, rd)?).into_owned())
}

/// Read the UUID from the payload
/// It is represented as an Array[bool, bytes] where first bool indicates whether following bytes
/// are UUID or just bytes that should be treated as a string (for cases where ID is not a valid
/// UUID)
fn read_uuid(rd: &mut &[u8]) -> Result<String, TokenProviderError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixArray(_) => {
            match read_marker(rd).map_err(ValueReadError::from)? {
                Marker::True => {
                    // This is uuid as bytes
                    // Technically we may fail reading it into bytes, but python part is
                    // responsible that it doesn not happen
                    if let Marker::Bin8 = read_marker(rd).map_err(ValueReadError::from)? {
                        return Ok(Uuid::try_from(read_bin_data(read_pfix(rd)?.into(), rd)?)?
                            .as_simple()
                            .to_string());
                    }
                }
                Marker::False => {
                    // This is not uuid
                    if let Marker::Bin8 = read_marker(rd).map_err(ValueReadError::from)? {
                        return Ok(String::from_utf8_lossy(&read_bin_data(
                            read_pfix(rd)?.into(),
                            rd,
                        )?)
                        .to_string());
                    }
                }
                _ => {
                    return Err(TokenProviderError::InvalidTokenUuid);
                }
            }
        }
        Marker::FixStr(len) => return Ok(read_str_data(len.into(), rd)?),
        other => {
            return Err(TokenProviderError::InvalidTokenUuidMarker(other));
        }
    }
    Err(TokenProviderError::InvalidTokenUuid)
}

/// Read the time represented as a f64 of the UTC seconds
fn read_time(rd: &mut &[u8]) -> Result<DateTime<Utc>, TokenProviderError> {
    DateTime::from_timestamp(read_f64(rd)?.round() as i64, 0)
        .ok_or(TokenProviderError::InvalidToken)
}

/// Decode the integer into the list of auth_methods
fn decode_auth_methods(
    value: usize,
    auth_map: &BTreeMap<usize, String>,
) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
    let mut results: Vec<String> = Vec::new();
    let mut auth: usize = value;
    for (idx, name) in auth_map.iter() {
        // (lbragstad): By dividing the method_int by each key in the
        // method_map, we know if the division results in an integer of 1, that
        // key was used in the construction of the total sum of the method_int.
        // In that case, we should confirm the key value and store it so we can
        // look it up later. Then we should take the remainder of what is
        // confirmed and the method_int and continue the process. In the end, we
        // should have a list of integers that correspond to indexes in our
        // method_map and we can reinflate the methods that the original
        // method_int represents.
        let result: usize = auth / idx;
        if result == 1 {
            results.push(name.into());
            auth -= idx;
        }
    }
    Ok(results.into_iter())
}

/// Decode array of audit ids from the payload
fn read_audit_ids(rd: &mut &[u8]) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
    if let Marker::FixArray(len) = read_marker(rd).map_err(ValueReadError::from)? {
        let mut result: Vec<String> = Vec::new();
        for _ in 0..len {
            if let Marker::Bin8 = read_marker(rd).map_err(ValueReadError::from)? {
                let dt = read_bin_data(read_pfix(rd)?.into(), rd)?;
                let audit_id: String = URL_SAFE.encode(dt).trim_end_matches('=').to_string();
                result.push(audit_id);
            } else {
                return Err(TokenProviderError::InvalidToken);
            }
        }
        return Ok(result.into_iter());
    }
    Err(TokenProviderError::InvalidToken)
}

impl FernetTokenProvider {
    /// Parse binary blob as MessagePack after encrypting it with Fernet
    fn parse(&self, rd: &mut &[u8]) -> Result<Token, TokenProviderError> {
        if let Marker::FixArray(_) = read_marker(rd).map_err(ValueReadError::from)? {
            match read_payload_token_type(rd)? {
                0 => Ok(UnscopedPayload::disassemble(rd, &self.auth_map)?.into()),
                1 => Ok(DomainPayload::disassemble(rd, &self.auth_map)?.into()),
                2 => Ok(ProjectPayload::disassemble(rd, &self.auth_map)?.into()),
                9 => Ok(ApplicationCredentialPayload::disassemble(rd, &self.auth_map)?.into()),
                other => Err(TokenProviderError::InvalidTokenType(other)),
            }
        } else {
            Err(TokenProviderError::InvalidToken)
        }
    }

    /// Get MultiFernet initialized with repository keys
    pub fn get_fernet(&self) -> Result<MultiFernet, TokenProviderError> {
        Ok(MultiFernet::new(
            self.utils
                .load_keys()?
                .into_iter()
                .filter_map(|x| Fernet::new(&x))
                .collect::<Vec<_>>(),
        ))
    }

    /// Load fernet keys from FS
    pub fn load_keys(&mut self) -> Result<(), TokenProviderError> {
        self.fernet = Some(self.get_fernet()?);
        Ok(())
    }

    /// Decrypt the token
    ///
    /// 1. Decrypt as Fernet
    /// 2. Unpack MessagePack payload
    pub fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError> {
        // TODO: Implement fernet keys change watching. Keystone loads them from FS on every
        // request and in the best case it costs 15µs.
        let payload = if let Some(fernet) = &self.fernet {
            fernet.decrypt(credential.as_ref())?
        } else {
            self.get_fernet()?.decrypt(credential.as_ref())?
        };
        self.parse(&mut payload.as_slice())
    }
}

/// Unscoped MsgPack payload
#[derive(Debug, Default)]
pub struct UnscopedPayload {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

impl From<UnscopedPayload> for Token {
    fn from(value: UnscopedPayload) -> Self {
        Self {
            user_id: value.user_id.clone(),
            methods: value.methods.clone(),
            expires_at: value.expires_at,
            audit_ids: value.audit_ids.clone(),
            ..Default::default()
        }
    }
}

impl UnscopedPayload {
    pub fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self, TokenProviderError> {
        // Order of reading is important
        let user_id = read_uuid(rd)?;
        let methods: Vec<String> = decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let expires_at = read_time(rd)?;
        let audit_ids: Vec<String> = read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
        })
    }
}

/// Domain scoped payload
#[derive(Debug, Default)]
pub struct DomainPayload {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub domain_id: String,
}

impl From<DomainPayload> for Token {
    fn from(value: DomainPayload) -> Self {
        Self {
            user_id: value.user_id.clone(),
            methods: value.methods.clone(),
            expires_at: value.expires_at,
            audit_ids: value.audit_ids.clone(),
            domain_id: Some(value.domain_id.clone()),
            ..Default::default()
        }
    }
}

impl DomainPayload {
    pub fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self, TokenProviderError> {
        // Order of reading is important
        let user_id = read_uuid(rd)?;
        let methods: Vec<String> = decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let domain_id = read_uuid(rd)?;
        let expires_at = read_time(rd)?;
        let audit_ids: Vec<String> = read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            domain_id,
            expires_at,
            audit_ids,
        })
    }
}

/// Project scoped payload
#[derive(Debug, Default)]
pub struct ProjectPayload {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub project_id: String,
}

impl From<ProjectPayload> for Token {
    fn from(value: ProjectPayload) -> Self {
        Self {
            user_id: value.user_id.clone(),
            methods: value.methods.clone(),
            expires_at: value.expires_at,
            audit_ids: value.audit_ids.clone(),
            project_id: Some(value.project_id.clone()),
            ..Default::default()
        }
    }
}

impl ProjectPayload {
    pub fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self, TokenProviderError> {
        // Order of reading is important
        let user_id = read_uuid(rd)?;
        let methods: Vec<String> = decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let project_id = read_uuid(rd)?;
        let expires_at = read_time(rd)?;
        let audit_ids: Vec<String> = read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            project_id,
            expires_at,
            audit_ids,
        })
    }
}

/// Application credential payload
#[derive(Debug, Default)]
pub struct ApplicationCredentialPayload {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub project_id: String,
    pub application_credential_id: String,
}

impl From<ApplicationCredentialPayload> for Token {
    fn from(value: ApplicationCredentialPayload) -> Self {
        Self {
            user_id: value.user_id.clone(),
            methods: value.methods.clone(),
            expires_at: value.expires_at,
            audit_ids: value.audit_ids.clone(),
            project_id: Some(value.project_id.clone()),
            application_credential_id: Some(value.application_credential_id.clone()),
            ..Default::default()
        }
    }
}

impl ApplicationCredentialPayload {
    pub fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self, TokenProviderError> {
        // Order of reading is important
        let user_id = read_uuid(rd)?;
        let methods: Vec<String> = decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let project_id = read_uuid(rd)?;
        let expires_at = read_time(rd)?;
        let audit_ids: Vec<String> = read_audit_ids(rd)?.into_iter().collect();
        let application_credential_id = read_uuid(rd)?;
        Ok(Self {
            user_id,
            methods,
            project_id,
            application_credential_id,
            expires_at,
            audit_ids,
        })
    }
}

impl TokenBackend for FernetTokenProvider {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.utils = FernetUtils {
            key_repository: config.fernet_tokens.key_repository.clone(),
            max_active_keys: config.fernet_tokens.max_active_keys,
        };
        self.auth_map = BTreeMap::from_iter(
            config
                .auth
                .methods
                .iter()
                .enumerate()
                .map(|(k, v)| (1 << k, v.clone())),
        );
        self.config = config;
    }

    /// Extract token
    fn extract(&self, credential: String) -> Result<Token, TokenProviderError> {
        self.decrypt(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        // write fernet key used to generate tokens in python
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();
        let mut config = Config::new(PathBuf::new()).unwrap();
        config.fernet_tokens.key_repository = keys_dir.into_path();
        config.auth.methods = vec![
            "password".into(),
            "token".into(),
            "openid".into(),
            "application_credential".into(),
        ];
        config
    }

    #[tokio::test]
    async fn test_decrypt_unscoped() {
        let token = "gAAAAABnt12vpnYCuUxl1lWQfTxwkBcZcgdK5wYons4BFHxxZLk326To5afinp29in7f5ZHR5K61Pl2voIjfbPKlL51KempshD4shfSje4RutbeXq-NT498eEcorzige5XBYGaoWuDTOKEDH2eXCMHhw9722j9iPP3Z4r_1Zlmcqq1n2tndmvsA";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let decrypted = backend.decrypt(token.into()).unwrap();
        assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
        assert!(decrypted.project_id.is_none());
        assert_eq!(decrypted.methods, vec!["token"]);
        assert_eq!(
            decrypted.expires_at.to_rfc3339(),
            "2025-02-20T17:40:13+00:00"
        );
        assert_eq!(
            decrypted.audit_ids,
            vec!["sfROvzgjTdmbo8xZdcze-g", "FL7FbzBKQsK115_4TyyiIw"]
        );
    }

    #[tokio::test]
    async fn test_decrypt_domain() {
        let token = "gAAAAABnt16C_ve4dDc7TeU857pwTXGJfGqNA4uJ308_2o_F9T_8WenNBatll0Q36wGz79dSI6RQnuN2PbK17wxQbn9jXscDh2ie3ZrW-WL5gG3gWK6FiPleAiU3kJN5mkskViJOIN-ZpP2B15fmZiYijelQ9TQuhQ";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let decrypted = backend.decrypt(token.into()).unwrap();
        assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
        assert_eq!(decrypted.domain_id, Some("default".into()));
        assert_eq!(decrypted.methods, vec!["password"]);
        assert_eq!(
            decrypted.expires_at.to_rfc3339(),
            "2025-02-20T17:55:30+00:00"
        );
        assert_eq!(decrypted.audit_ids, vec!["eikbCiM0SsO5P9d_GbVhBQ"]);
    }

    #[tokio::test]
    async fn test_decrypt_project() {
        let token = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let decrypted = backend.decrypt(token.into()).unwrap();
        assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
        assert_eq!(
            decrypted.project_id,
            Some("97cd761d581b485792a4afc8cc6a998d".into())
        );
        assert_eq!(decrypted.methods, vec!["password"]);
        assert_eq!(
            decrypted.expires_at.to_rfc3339(),
            "2025-02-17T17:49:53+00:00"
        );
        assert_eq!(decrypted.audit_ids, vec!["fhRNUHHPTkitISpEYkY_mQ"]);
    }

    #[tokio::test]
    async fn test_decrypt_application_credential() {
        let token = "gAAAAABnt11m57ZlI9JU0g2BKJw2EN-InbAIijcIG7SxvPATntgTlcTMwha-Fh7isNNIwDq2WaWglV1nYgftfoUK245ZnEJ0_gXaIhl6COhNommYv2Bs9PnJqfgrrxrIrB8rh4pfeyCtMkv5ePYgFFPyRFE37l3k7qL5p7qVhYT37yT1-K5lYAV0f6Vy70h3KX1HO0m6Rl90";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let decrypted = backend.decrypt(token.into()).unwrap();
        assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
        assert_eq!(
            decrypted.project_id,
            Some("97cd761d581b485792a4afc8cc6a998d".into())
        );
        assert_eq!(decrypted.methods, vec!["application_credential"]);
        assert_eq!(
            decrypted.expires_at.to_rfc3339(),
            "2025-02-20T17:50:46+00:00"
        );
        assert_eq!(decrypted.audit_ids, vec!["kD7Cwc8fSZuWNPZhy0fLVg"]);
        assert_eq!(
            decrypted.application_credential_id,
            Some("a67630c36e1b48839091c905177c5598".into())
        );
    }
}
