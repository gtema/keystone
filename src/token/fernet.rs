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

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use fernet::{Fernet, MultiFernet};
//use rmp::decode;
use chrono::{DateTime, Utc};
use rmpv::Value;
use std::collections::BTreeMap;
use tracing::debug;
use uuid::Uuid;

use crate::config::Config;
use crate::token::{
    fernet_utils::FernetUtils,
    types::{Token, TokenBackend},
    TokenProviderError,
};

#[derive(Clone, Debug, Default)]
pub struct FernetTokenProvider {
    pub config: Config,
    pub utils: FernetUtils,
    pub auth_map: BTreeMap<usize, String>,
}

#[async_trait]
impl TokenBackend for FernetTokenProvider {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.utils = FernetUtils {
            key_repository: config.fernet_tokens.key_repository.clone().into(),
            max_active_keys: config.fernet_tokens.max_active_keys,
        };
        self.config = config;
        self.auth_map = BTreeMap::from([(1, "password".into()), (2, "token".into())]);
    }

    /// Decrypt the token
    async fn decrypt(&self, credential: String) -> Result<Token, TokenProviderError> {
        let multi_fernet = MultiFernet::new(
            self.utils
                .load_keys()
                .await?
                .into_iter()
                .filter_map(|x| Fernet::new(&x))
                .collect::<Vec<_>>(),
        );

        let decrypt = multi_fernet.decrypt(credential.as_ref())?;
        let data: Vec<Value> = rmpv::decode::read_value(&mut &decrypt[..])?
            .as_array()
            .ok_or(TokenProviderError::InvalidToken)?
            .to_vec();
        debug!("Decrypted token data is {:?}", data);

        match data
            .first()
            .ok_or(TokenProviderError::InvalidToken)?
            .as_u64()
        {
            Some(0) => {
                // Unscoped
                Unscoped::disassemble(&self.auth_map, &data)
            }
            //Some(1) => {
            //    // Domain scope
            //    debug!("is 1");
            //}
            Some(2) => {
                // Project scope
                ProjectScope::disassemble(&self.auth_map, &data)
            }
            //Some(3) => {
            //    // Trust scope
            //    debug!("is 3");
            //}
            //Some(4) => {
            //    // Federation unscoped
            //}
            //Some(5) => {
            //    // Federation project
            //}
            //Some(6) => {
            //    // Federation domain
            //}
            //Some(7) => {
            //    // OAuth
            //}
            //Some(8) => {
            //    // System
            //}
            //Some(9) => {
            //    // AppCred
            //}
            //Some(10) => {
            //    // OAuth2
            //}
            Some(other) => {
                // OAuth2
                debug!("other {:?}", other);
                return Err(TokenProviderError::InvalidToken);
            }
            None => {
                debug!("no ver");
                return Err(TokenProviderError::InvalidToken);
            }
        }
    }
}

pub struct Unscoped {}
pub struct ProjectScope {}

fn read_uuid(value: &Value) -> Result<String, TokenProviderError> {
    if let Some(array) = value.as_array() {
        let uuid_data = array.get(1).ok_or(TokenProviderError::InvalidToken)?;
        let uid = if uuid_data.is_bin() {
            Uuid::try_from(
                uuid_data
                    .as_slice()
                    .ok_or(TokenProviderError::InvalidToken)?
                    .to_vec(),
            )?
        } else if uuid_data.is_str() {
            Uuid::parse_str(uuid_data.as_str().ok_or(TokenProviderError::InvalidToken)?)?
        } else {
            return Err(TokenProviderError::InvalidToken);
        };
        return Ok(uid.as_simple().to_string());
    }
    Err(TokenProviderError::InvalidToken)
}

fn decode_methods(
    auth_map: &BTreeMap<usize, String>,
    auth: usize,
) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
    let mut results: Vec<String> = Vec::new();
    let mut auth: usize = auth.into();
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

fn get_methods(
    auth_map: &BTreeMap<usize, String>,
    value: &Value,
) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
    let mut results: Vec<String> = Vec::new();
    let mut auth: usize = value
        .as_u64()
        .ok_or(TokenProviderError::InvalidToken)?
        .try_into()?;
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

fn get_time(value: &Value) -> Result<DateTime<Utc>, TokenProviderError> {
    value
        .as_f64()
        .and_then(|x| DateTime::from_timestamp(x.round() as i64, 0))
        .ok_or(TokenProviderError::InvalidToken)
}

fn get_audit_ids(value: &Value) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
    Ok(value
        .as_array()
        .ok_or(TokenProviderError::InvalidToken)?
        .iter()
        .filter_map(|val| val.as_slice())
        .map(|val| URL_SAFE.encode(val).trim_end_matches('=').to_string())
        .collect::<Vec<_>>())
}

impl Unscoped {
    pub fn disassemble(
        auth_map: &BTreeMap<usize, String>,
        value: &[Value],
    ) -> Result<Token, TokenProviderError> {
        Ok(Token {
            user_id: read_uuid(value.get(1).ok_or(TokenProviderError::InvalidToken)?)?,
            methods: get_methods(
                auth_map,
                value.get(2).ok_or(TokenProviderError::InvalidToken)?,
            )?
            .into_iter()
            .collect(),
            expires_at: get_time(value.get(3).ok_or(TokenProviderError::InvalidToken)?)?,
            audit_ids: get_audit_ids(value.get(4).ok_or(TokenProviderError::InvalidToken)?)?
                .into_iter()
                .collect(),
            ..Default::default()
        })
    }
}

impl ProjectScope {
    pub fn disassemble(
        auth_map: &BTreeMap<usize, String>,
        value: &[Value],
    ) -> Result<Token, TokenProviderError> {
        let 
        Ok(Token {
            user_id: read_uuid(value.get(1).ok_or(TokenProviderError::InvalidToken)?)?,
            methods: get_methods(
                auth_map,
                value.get(2).ok_or(TokenProviderError::InvalidToken)?,
            )?
            .into_iter()
            .collect(),
            expires_at: get_time(value.get(4).ok_or(TokenProviderError::InvalidToken)?)?,
            audit_ids: get_audit_ids(value.get(5).ok_or(TokenProviderError::InvalidToken)?)?
                .into_iter()
                .collect(),
            project_id: Some(read_uuid(
                value.get(3).ok_or(TokenProviderError::InvalidToken)?,
            )?),
            ..Default::default()
        })
    }
}
