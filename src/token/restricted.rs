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
use serde::Serialize;
use std::io::Write;

use crate::assignment::types::Role;
use crate::identity::types::UserResponse;
use crate::resource::types::Project;
use crate::token::{
    error::TokenProviderError,
    fernet::{FernetTokenProvider, MsgPackToken},
    fernet_utils,
    types::Token,
};

/// Restricted token payload
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize)]
#[builder(setter(into))]
pub struct RestrictedPayload {
    /// User ID.
    pub user_id: String,
    /// Authentication methods used to obtain the token.
    #[builder(default, setter(name = _methods))]
    pub methods: Vec<String>,
    /// Token audit IDs.
    #[builder(default, setter(name = _audit_ids))]
    pub audit_ids: Vec<String>,
    /// Token expiration datetime in UTC.
    pub expires_at: DateTime<Utc>,
    /// ID of the token restrictions.
    pub token_restriction_id: String,
    /// Project ID scope for the token.
    pub project_id: String,
    /// Whether the token can be renewed.
    pub allow_renew: bool,
    /// Whether the token can be rescoped.
    pub allow_rescope: bool,

    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub roles: Option<Vec<Role>>,
    #[builder(default)]
    pub project: Option<Project>,
}

impl RestrictedPayloadBuilder {
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

impl From<RestrictedPayload> for Token {
    fn from(value: RestrictedPayload) -> Self {
        Self::Restricted(value)
    }
}

impl MsgPackToken for RestrictedPayload {
    type Token = Self;

    fn assemble<W: Write>(
        &self,
        wd: &mut W,
        fernet_provider: &FernetTokenProvider,
    ) -> Result<(), TokenProviderError> {
        fernet_utils::write_uuid(wd, &self.user_id)?;
        write_pfix(
            wd,
            fernet_provider.encode_auth_methods(self.methods.clone())?,
        )
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
        fernet_utils::write_uuid(wd, &self.token_restriction_id)?;
        fernet_utils::write_time(wd, self.expires_at)?;
        fernet_utils::write_uuid(wd, &self.project_id)?;
        fernet_utils::write_bool(wd, self.allow_renew)?;
        fernet_utils::write_bool(wd, self.allow_rescope)?;
        fernet_utils::write_audit_ids(wd, self.audit_ids.clone())?;

        Ok(())
    }

    fn disassemble(
        rd: &mut &[u8],
        fernet_provider: &FernetTokenProvider,
    ) -> Result<Self::Token, TokenProviderError> {
        // Order of reading is important
        let user_id = fernet_utils::read_uuid(rd)?;
        let methods: Vec<String> = fernet_provider
            .decode_auth_methods(read_pfix(rd)?)?
            .into_iter()
            .collect();
        let token_restriction_id = fernet_utils::read_uuid(rd)?;
        let expires_at = fernet_utils::read_time(rd)?;
        let project_id = fernet_utils::read_uuid(rd)?;
        let allow_renew = fernet_utils::read_bool(rd)?;
        let allow_rescope = fernet_utils::read_bool(rd)?;
        let audit_ids: Vec<String> = fernet_utils::read_audit_ids(rd)?.into_iter().collect();
        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
            token_restriction_id,
            project_id,
            allow_renew,
            allow_rescope,

            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Local, SubsecRound};
    use uuid::Uuid;

    use super::super::tests::setup_config;
    use super::*;

    #[test]
    fn test_roundtrip() {
        let token = RestrictedPayload {
            user_id: Uuid::new_v4().simple().to_string(),
            methods: vec!["openid".into()],
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: Local::now().trunc_subsecs(0).into(),
            token_restriction_id: "trid".into(),
            project_id: "pid".into(),
            allow_renew: true,
            allow_rescope: true,
            ..Default::default()
        };

        let provider = FernetTokenProvider::new(setup_config());

        let mut buf = vec![];
        token.assemble(&mut buf, &provider).unwrap();
        let encoded_buf = buf.clone();
        let decoded =
            RestrictedPayload::disassemble(&mut encoded_buf.as_slice(), &provider).unwrap();
        assert_eq!(token, decoded);
    }
}
