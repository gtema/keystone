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

use chrono::Local;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use webauthn_rs::prelude::Passkey;

use crate::db::entity::{prelude::WebauthnCredential as DbPasskey, webauthn_credential};
use crate::identity::backends::error::IdentityDatabaseError;

pub(super) async fn create(
    db: &DatabaseConnection,
    user_id: &str,
    passkey: Passkey,
) -> Result<(), IdentityDatabaseError> {
    let now = Local::now().naive_utc();
    let entry = webauthn_credential::ActiveModel {
        id: NotSet,
        user_id: Set(user_id.to_string()),
        credential_id: Set(passkey.cred_id().escape_ascii().to_string()),
        passkey: Set(serde_json::to_string(&passkey)?),
        r#type: Set("cross-platform".to_string()),
        aaguid: NotSet,
        created_at: Set(now),
        last_used_at: NotSet,
        last_updated_at: NotSet,
    };
    let _ = entry.insert(db).await?;
    Ok(())
}

pub async fn list(
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<Vec<Passkey>, IdentityDatabaseError> {
    let res: Result<Vec<Passkey>, _> = DbPasskey::find()
        .filter(webauthn_credential::Column::UserId.eq(user_id))
        .all(db)
        .await?
        .into_iter()
        .map(|x| serde_json::from_str::<Passkey>(&x.passkey))
        .collect();
    Ok(res?)
}

//#[cfg(test)]
//mod tests {
//    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
//    use serde_json::json;
//
//    use super::*;
//}
