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
use rmp::{decode::read_pfix, encode::write_pfix};
use std::collections::BTreeMap;
use std::io::Write;

use crate::token::{
    error::TokenProviderError,
    fernet::{self, MsgPackToken},
    fernet_utils,
    types::Token,
};

#[derive(Builder, Clone, Debug, Default, PartialEq)]
pub struct DomainScopeToken {
    pub user_id: String,
    #[builder(default, setter(name = _methods))]
    pub methods: Vec<String>,
    #[builder(default, setter(name = _audit_ids))]
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub domain_id: String,
}

impl DomainScopeTokenBuilder {
    pub fn methods<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.methods
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }

    pub fn audit_ids<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.audit_ids
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }
}

impl From<DomainScopeToken> for Token {
    fn from(value: DomainScopeToken) -> Self {
        Token::DomainScope(value)
    }
}

impl MsgPackToken for DomainScopeToken {
    type Token = DomainScopeToken;

    fn assemble<W: Write>(
        &self,
        wd: &mut W,
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<(), TokenProviderError> {
        fernet_utils::write_uuid(wd, &self.user_id)?;
        write_pfix(
            wd,
            fernet::encode_auth_methods(self.methods.clone(), auth_map)? as u8,
        )
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
        fernet_utils::write_uuid(wd, &self.domain_id)?;
        fernet_utils::write_time(wd, self.expires_at)?;
        fernet_utils::write_audit_ids(wd, self.audit_ids.clone())?;

        Ok(())
    }

    fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self::Token, TokenProviderError> {
        // Order of reading is important
        let user_id = fernet_utils::read_uuid(rd)?;
        let methods: Vec<String> = fernet::decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let domain_id = fernet_utils::read_uuid(rd)?;
        let expires_at = fernet_utils::read_time(rd)?;
        let audit_ids: Vec<String> = fernet_utils::read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
            domain_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Local, SubsecRound};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn test_roundtrip() {
        let token = DomainScopeToken {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["password".into()],
            domain_id: Uuid::new_v4().simple().to_string(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
        };
        let auth_map = BTreeMap::from([(1, "password".into())]);
        let mut buf = vec![];
        token.assemble(&mut buf, &auth_map).unwrap();
        let encoded_buf = buf.clone();
        let decoded =
            DomainScopeToken::disassemble(&mut encoded_buf.as_slice(), &auth_map).unwrap();
        assert_eq!(token, decoded);
    }
}
