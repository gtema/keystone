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

use crate::config::Config;
use crate::db::entity::{prelude::User as DbUser, user};
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::UserCreate;

pub(super) async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: &UserCreate,
) -> Result<user::Model, IdentityDatabaseError> {
    let now = Local::now().naive_utc();
    // Set last_active to now if compliance disabling is on
    let last_active_at = if let Some(true) = &user.enabled {
        if conf
            .security_compliance
            .disable_user_account_days_inactive
            .is_some()
        {
            Set(Some(now.date()))
        } else {
            NotSet
        }
    } else {
        NotSet
    };

    let entry: user::ActiveModel = user::ActiveModel {
        id: Set(user.id.clone()),
        enabled: Set(user.enabled),
        extra: Set(Some(serde_json::to_string(&user.extra)?)),
        default_project_id: Set(user.default_project_id.clone()),
        last_active_at,
        created_at: Set(Some(now)),
        domain_id: Set(user.domain_id.clone()),
    };
    let db_user: user::Model = entry.insert(db).await?;
    Ok(db_user)
}

pub async fn delete(
    _conf: &Config,
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<(), IdentityDatabaseError> {
    let res = DbUser::delete_by_id(user_id).exec(db).await?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(IdentityDatabaseError::UserNotFound(user_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use crate::identity::Config;

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        delete(&config, &db, "id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "user" WHERE "user"."id" = $1"#,
                ["id".into()]
            ),]
        );
    }
}
