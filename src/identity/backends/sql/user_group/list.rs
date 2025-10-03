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
use sea_orm::query::*;

use crate::db::entity::{
    group,
    prelude::{Group as DbGroup, UserGroupMembership as DbUserGroupMembership},
    user_group_membership,
};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};
use crate::identity::types::Group;

/// List all groups the user is member of.
pub async fn list_user_groups<S: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: S,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    let groups: Vec<(user_group_membership::Model, Vec<group::Model>)> =
        DbUserGroupMembership::find()
            .filter(user_group_membership::Column::UserId.eq(user_id.as_ref()))
            .find_with_related(DbGroup)
            .all(db)
            .await
            .map_err(|e| db_err(e, "listing groups the user is currently in"))?;

    let results: Vec<Group> = groups
        .into_iter()
        .flat_map(|(_, x)| x.into_iter())
        .map(Into::into)
        .collect();
    Ok(results)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    fn get_group_mock<S: AsRef<str>>(id: S) -> group::Model {
        group::Model {
            id: id.as_ref().to_string(),
            domain_id: "foo_domain".into(),
            name: "group".into(),
            description: Some("fake".into()),
            extra: Some("{\"foo\": \"bar\"}".into()),
        }
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![], vec![get_group_mock("1"), get_group_mock("2")]])
            .into_connection();
        assert_eq!(list_user_groups(&db, "foo").await.unwrap(), vec![]);

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user_group_membership"."user_id" AS "A_user_id", "user_group_membership"."group_id" AS "A_group_id", "group"."id" AS "B_id", "group"."domain_id" AS "B_domain_id", "group"."name" AS "B_name", "group"."description" AS "B_description", "group"."extra" AS "B_extra" FROM "user_group_membership" LEFT JOIN "group" ON "user_group_membership"."group_id" = "group"."id" WHERE "user_group_membership"."user_id" = $1 ORDER BY "user_group_membership"."user_id" ASC, "user_group_membership"."group_id" ASC"#,
                ["foo".into()]
            ),]
        );
    }
}
