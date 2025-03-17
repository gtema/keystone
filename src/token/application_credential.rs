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
use std::collections::BTreeMap;

use rmp::decode::*;

use crate::token::{
    error::TokenProviderError,
    fernet::{self, MsgPackToken},
    fernet_utils,
    types::Token,
};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplicationCredentialToken {
    pub user_id: String,
    pub methods: Vec<String>,
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub project_id: String,
    pub application_credential_id: String,
}

impl From<ApplicationCredentialToken> for Token {
    fn from(value: ApplicationCredentialToken) -> Self {
        Token::ApplicationCredential(value)
    }
}

impl MsgPackToken for ApplicationCredentialToken {
    type Token = ApplicationCredentialToken;

    fn disassemble(
        rd: &mut &[u8],
        auth_map: &BTreeMap<usize, String>,
    ) -> Result<Self::Token, TokenProviderError> {
        // Order of reading is important
        let user_id = fernet_utils::read_uuid(rd)?;
        let methods: Vec<String> = fernet::decode_auth_methods(read_pfix(rd)?.into(), auth_map)?
            .into_iter()
            .collect();
        let project_id = fernet_utils::read_uuid(rd)?;
        let expires_at = fernet_utils::read_time(rd)?;
        let audit_ids: Vec<String> = fernet_utils::read_audit_ids(rd)?.into_iter().collect();
        let application_credential_id = fernet_utils::read_uuid(rd)?;

        Ok(Self {
            user_id,
            methods,
            expires_at,
            audit_ids,
            project_id,
            application_credential_id,
        })
    }
}
