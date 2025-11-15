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
//! Revoke provider: database backend.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use super::RevokeBackend;
use crate::config::Config;
use crate::db::entity::revocation_event as db_revocation_event;
use crate::keystone::ServiceState;
use crate::revoke::RevokeProviderError;
use crate::revoke::backend::error::RevokeDatabaseError;
use crate::token::types::Token;

mod list;

/// Sql Database revocation backend.
#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

impl TryFrom<db_revocation_event::Model> for RevocationEvent {
    type Error = RevokeDatabaseError;
    fn try_from(value: db_revocation_event::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            domain_id: value.domain_id,
            project_id: value.project_id,
            user_id: value.user_id,
            role_id: value.role_id,
            trust_id: value.trust_id,
            consumer_id: value.consumer_id,
            access_token_id: value.access_token_id,
            issued_before: value.issued_before.and_utc(),
            expires_at: value.expires_at.map(|expires_at| expires_at.and_utc()),
            revoked_at: value.revoked_at.and_utc(),
            audit_id: value.audit_id,
            audit_chain_id: value.audit_chain_id,
        })
    }
}

#[async_trait]
impl RevokeBackend for SqlBackend {
    /// Set config.
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Check the token for being revoked.
    ///
    /// List not expired revocation records that invalidate the token and returns true if there is
    /// at least one such record.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError> {
        // Check for the token revocation events.
        if list::count(&state.db, &token.try_into()?).await? > 0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Revocation event.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct RevocationEvent {
    pub domain_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    pub trust_id: Option<String>,
    pub consumer_id: Option<String>,
    pub access_token_id: Option<String>,
    pub issued_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: DateTime<Utc>,
    pub audit_id: Option<String>,
    pub audit_chain_id: Option<String>,
}

/// Revocation list parameters.
///
/// It may be necessary to list revocation events not related to the certain token.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
struct RevocationEventListParameters {
    //pub access_token_id: Option<String>,
    //pub audit_chain_id: Option<String>,
    #[builder(default)]
    pub audit_id: Option<String>,
    //pub consumer_id: Option<String>,
    #[builder(default)]
    pub domain_id: Option<String>,
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[builder(default)]
    pub issued_before: Option<DateTime<Utc>>,
    #[builder(default)]
    pub project_id: Option<String>,
    #[builder(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    //pub role_id: Option<String>,
    //pub trust_id: Option<String>,
    #[builder(default)]
    pub user_id: Option<Vec<String>>,
}

impl TryFrom<&Token> for RevocationEventListParameters {
    type Error = RevokeProviderError;
    fn try_from(value: &Token) -> Result<Self, Self::Error> {
        // TODO: for trust token user_id can be trustee_id or trustor_id
        Ok(Self {
            //access_token_id: None,
            //audit_chain_id: None,
            audit_id: Some(
                value
                    .audit_ids()
                    .first()
                    .ok_or_else(|| RevokeProviderError::TokenHasNoAuditId)?,
            )
            .cloned(),
            //consumer_id: None,
            domain_id: value.domain().map(|domain| domain.id.clone()),
            expires_at: None,
            issued_before: Some(*value.issued_at()),
            project_id: value.project_id().cloned(),
            revoked_at: None,
            //role_id: None,
            //trust_id: None,
            user_id: Some(vec![value.user_id().clone()]),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::entity::revocation_event as db_revocation_event;
    use chrono::NaiveDateTime;

    pub(super) fn get_mock() -> db_revocation_event::Model {
        db_revocation_event::Model {
            id: 1i32,
            domain_id: Some("did".into()),
            project_id: Some("pid".into()),
            user_id: Some("uid".into()),
            role_id: Some("rid".into()),
            trust_id: Some("trust_id".into()),
            consumer_id: Some("consumer_id".into()),
            access_token_id: Some("access_token_id".into()),
            issued_before: NaiveDateTime::default(),
            expires_at: Some(NaiveDateTime::default()),
            revoked_at: NaiveDateTime::default(),
            audit_id: Some("audit_id".into()),
            audit_chain_id: Some("audit_chain_id".into()),
        }
    }
}
