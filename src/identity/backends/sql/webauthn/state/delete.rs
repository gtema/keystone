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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::prelude::WebauthnState as DbPasskeyState;
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn delete<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<(), IdentityDatabaseError> {
    DbPasskeyState::delete_by_id(user_id.as_ref())
        .exec(db)
        .await
        .map_err(|e| db_err(e, "deleting webauthn state record"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete(&db, "id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "webauthn_state" WHERE "webauthn_state"."user_id" = $1"#,
                ["id".into()]
            ),]
        );
    }
}
