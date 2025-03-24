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

use bytes::Bytes;
use fernet::{Fernet, MultiFernet};
use rmp::{
    Marker,
    decode::{ValueReadError, read_marker, read_u8},
    encode::{write_array_len, write_pfix},
};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::io::Write;

use crate::config::Config;
use crate::token::{
    TokenProviderError, application_credential::ApplicationCredentialToken,
    domain_scoped::DomainScopeToken, fernet_utils::FernetUtils, project_scoped::ProjectScopeToken,
    types::*, unscoped::UnscopedToken,
};

#[derive(Default, Clone)]
pub struct FernetTokenProvider {
    config: Config,
    utils: FernetUtils,
    fernet: Option<MultiFernet>,
    auth_map: BTreeMap<usize, String>,
}

pub trait MsgPackToken {
    type Token;

    /// Construct MsgPack payload for the Token
    fn assemble<W: Write>(
        &self,
        _wd: &mut W,
        _auth_map: &BTreeMap<usize, String>,
    ) -> Result<(), TokenProviderError> {
        Ok(())
    }

    /// Parse MsgPack payload into the Token
    fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self::Token, TokenProviderError>;
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

/// Decode the integer into the list of auth_methods
pub(crate) fn decode_auth_methods(
    value: usize,
    auth_map: &BTreeMap<usize, String>,
) -> Result<impl IntoIterator<Item = String> + use<>, TokenProviderError> {
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

/// Encode the list of auth_methods into a single integer
pub(crate) fn encode_auth_methods<I: IntoIterator<Item = String>>(
    methods: I,
    auth_map: &BTreeMap<usize, String>,
) -> Result<usize, TokenProviderError> {
    let me: HashSet<String> = HashSet::from_iter(methods);
    let res = auth_map
        .iter()
        .fold(0, |acc, (k, v)| acc + if me.contains(v) { *k } else { 0 });
    Ok(res)
}

impl FernetTokenProvider {
    /// Parse binary blob as MessagePack after encrypting it with Fernet
    fn decode(&self, rd: &mut &[u8]) -> Result<Token, TokenProviderError> {
        if let Marker::FixArray(_) = read_marker(rd).map_err(ValueReadError::from)? {
            match read_payload_token_type(rd)? {
                0 => Ok(UnscopedToken::disassemble(rd, &self.auth_map)?.into()),
                1 => Ok(DomainScopeToken::disassemble(rd, &self.auth_map)?.into()),
                2 => Ok(ProjectScopeToken::disassemble(rd, &self.auth_map)?.into()),
                9 => Ok(ApplicationCredentialToken::disassemble(rd, &self.auth_map)?.into()),
                other => Err(TokenProviderError::InvalidTokenType(other)),
            }
        } else {
            Err(TokenProviderError::InvalidToken)
        }
    }

    /// Encode Token as binary blob as MessagePack
    fn encode(&self, token: &Token) -> Result<Bytes, TokenProviderError> {
        let mut buf = vec![];
        match token {
            Token::Unscoped(data) => {
                write_array_len(&mut buf, 5)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 0)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, &self.auth_map)?;
            }
            Token::DomainScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 1)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, &self.auth_map)?;
            }
            Token::ProjectScope(data) => {
                write_array_len(&mut buf, 6)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 2)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, &self.auth_map)?;
            }
            Token::ApplicationCredential(data) => {
                write_array_len(&mut buf, 7)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                write_pfix(&mut buf, 9)
                    .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
                data.assemble(&mut buf, &self.auth_map)?;
            }
        }
        Ok(buf.into())
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
    pub fn decrypt(&self, credential: &str) -> Result<Token, TokenProviderError> {
        // TODO: Implement fernet keys change watching. Keystone loads them from FS on every
        // request and in the best case it costs 15µs.
        let payload = match &self.fernet {
            Some(fernet) => fernet.decrypt(credential)?,
            _ => self.get_fernet()?.decrypt(credential)?,
        };
        self.decode(&mut payload.as_slice())
    }

    /// Encrypt the token
    pub fn encrypt(&self, token: &Token) -> Result<String, TokenProviderError> {
        let payload = self.encode(token)?;
        let res = match &self.fernet {
            Some(fernet) => fernet.encrypt(&payload),
            _ => self.get_fernet()?.encrypt(&payload),
        };
        Ok(res)
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

    /// Decrypt the token
    fn decode(&self, credential: &str) -> Result<Token, TokenProviderError> {
        self.decrypt(credential)
    }

    /// Encrypt the token
    fn encode(&self, token: &Token) -> Result<String, TokenProviderError> {
        self.encrypt(token)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use chrono::{Local, SubsecRound};
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use uuid::Uuid;

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
        let config = crate::tests::token::setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        if let Token::Unscoped(decrypted) = backend.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.methods, vec!["token"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:40:13+00:00"
            );
            assert_eq!(
                decrypted.audit_ids,
                vec!["sfROvzgjTdmbo8xZdcze-g", "FL7FbzBKQsK115_4TyyiIw"]
            );
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_unscoped_roundtrip() {
        let token = Token::Unscoped(UnscopedToken {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
        });

        let mut backend = FernetTokenProvider::default();
        let config = crate::tests::token::setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let encrypted = backend.encrypt(&token).unwrap();
        let dec_token = backend.decrypt(&encrypted).unwrap();
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_domain() {
        let token = "gAAAAABnt16C_ve4dDc7TeU857pwTXGJfGqNA4uJ308_2o_F9T_8WenNBatll0Q36wGz79dSI6RQnuN2PbK17wxQbn9jXscDh2ie3ZrW-WL5gG3gWK6FiPleAiU3kJN5mkskViJOIN-ZpP2B15fmZiYijelQ9TQuhQ";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        if let Token::DomainScope(decrypted) = backend.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.domain_id, "default");
            assert_eq!(decrypted.methods, vec!["password"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:55:30+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["eikbCiM0SsO5P9d_GbVhBQ"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_domain_roundtrip() {
        let token = Token::DomainScope(DomainScopeToken {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            domain_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut backend = FernetTokenProvider::default();
        let config = crate::tests::token::setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let encrypted = backend.encrypt(&token).unwrap();
        let dec_token = backend.decrypt(&encrypted).unwrap();
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_project() {
        let token = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        if let Token::ProjectScope(decrypted) = backend.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.project_id, "97cd761d581b485792a4afc8cc6a998d");
            assert_eq!(decrypted.methods, vec!["password"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-17T17:49:53+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["fhRNUHHPTkitISpEYkY_mQ"]);
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_project_roundtrip() {
        let token = Token::ProjectScope(ProjectScopeToken {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut backend = FernetTokenProvider::default();
        let config = crate::tests::token::setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let encrypted = backend.encrypt(&token).unwrap();
        let dec_token = backend.decrypt(&encrypted).unwrap();
        assert_eq!(token, dec_token);
    }

    #[tokio::test]
    async fn test_decrypt_application_credential() {
        let token = "gAAAAABnt11m57ZlI9JU0g2BKJw2EN-InbAIijcIG7SxvPATntgTlcTMwha-Fh7isNNIwDq2WaWglV1nYgftfoUK245ZnEJ0_gXaIhl6COhNommYv2Bs9PnJqfgrrxrIrB8rh4pfeyCtMkv5ePYgFFPyRFE37l3k7qL5p7qVhYT37yT1-K5lYAV0f6Vy70h3KX1HO0m6Rl90";

        let mut backend = FernetTokenProvider::default();
        let config = setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        if let Token::ApplicationCredential(decrypted) = backend.decrypt(token).unwrap() {
            assert_eq!(decrypted.user_id, "4b7d364ad87d400bbd91798e3c15e9c2");
            assert_eq!(decrypted.project_id, "97cd761d581b485792a4afc8cc6a998d");
            assert_eq!(decrypted.methods, vec!["application_credential"]);
            assert_eq!(
                decrypted.expires_at.to_rfc3339(),
                "2025-02-20T17:50:46+00:00"
            );
            assert_eq!(decrypted.audit_ids, vec!["kD7Cwc8fSZuWNPZhy0fLVg"]);
            assert_eq!(
                decrypted.application_credential_id,
                "a67630c36e1b48839091c905177c5598"
            );
        } else {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_application_credential_roundtrip() {
        let token = Token::ApplicationCredential(ApplicationCredentialToken {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["application_credential".into()],
            project_id: Uuid::new_v4().simple().to_string(),
            application_credential_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            ..Default::default()
        });

        let mut backend = FernetTokenProvider::default();
        let config = crate::tests::token::setup_config();
        backend.set_config(config);
        backend.load_keys().unwrap();

        let encrypted = backend.encrypt(&token).unwrap();
        let dec_token = backend.decrypt(&encrypted).unwrap();
        assert_eq!(token, dec_token);
    }
}
