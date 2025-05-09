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
use serde_json::Value;
use serde_json::json;

use crate::db::entity::{
    group,
    prelude::{Group as DbGroup, UserGroupMembership as DbUserGroupMembership},
    user_group_membership,
};
use crate::identity::Config;
use crate::identity::backends::sql::IdentityDatabaseError;
use crate::identity::types::{Group, GroupCreate, GroupListParameters};

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &GroupListParameters,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    // Prepare basic selects
    let mut group_select = DbGroup::find();

    if let Some(domain_id) = &params.domain_id {
        group_select = group_select.filter(group::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        group_select = group_select.filter(group::Column::Name.eq(name));
    }

    let db_groups: Vec<group::Model> = group_select.all(db).await?;
    let results: Vec<Group> = db_groups.into_iter().map(Into::into).collect();

    Ok(results)
}

pub async fn get<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    group_id: S,
) -> Result<Option<Group>, IdentityDatabaseError> {
    Ok(DbGroup::find_by_id(group_id.as_ref())
        .one(db)
        .await?
        .map(Into::into))
}

pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    group: GroupCreate,
) -> Result<Group, IdentityDatabaseError> {
    let entry = group::ActiveModel {
        id: Set(group.id.clone().unwrap_or_default()),
        domain_id: Set(group.domain_id.clone()),
        name: Set(group.name.clone()),
        description: Set(group.description.clone()),
        extra: Set(Some(serde_json::to_string(&group.extra)?)),
    };

    let db_entry: group::Model = entry.insert(db).await?;

    Ok(db_entry.into())
}

pub async fn delete<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    group_id: S,
) -> Result<(), IdentityDatabaseError> {
    let res = DbGroup::delete_by_id(group_id.as_ref()).exec(db).await?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(IdentityDatabaseError::GroupNotFound(
            group_id.as_ref().to_string(),
        ))
    }
}

impl From<group::Model> for Group {
    fn from(value: group::Model) -> Self {
        Group {
            id: value.id.clone(),
            name: value.name.clone(),
            description: value.description.clone(),
            domain_id: value.domain_id.clone(),
            extra: value
                .extra
                .map(|x| serde_json::from_str::<Value>(&x).unwrap_or(json!(true))),
        }
    }
}

pub async fn list_for_user<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    user_id: S,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    let groups: Vec<(user_group_membership::Model, Vec<group::Model>)> =
        DbUserGroupMembership::find()
            .filter(user_group_membership::Column::UserId.eq(user_id.as_ref()))
            .find_with_related(DbGroup)
            .all(db)
            .await?;

    let results: Vec<Group> = groups
        .into_iter()
        .flat_map(|(_, x)| x.into_iter())
        .map(Into::into)
        .collect();
    Ok(results)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use crate::db::entity::group;
    use crate::identity::Config;
    use crate::identity::types::group::GroupListParametersBuilder;

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
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_group_mock("1")],
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(&config, &db, &GroupListParameters::default())
                .await
                .unwrap(),
            vec![Group {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "group".into(),
                description: Some("fake".into()),
                extra: Some(json!({"foo": "bar"}))
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group""#,
                //["1".into(), 1u64.into()]
                []
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_with_filters() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<group::Model>::new()])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(
                &config,
                &db,
                &GroupListParametersBuilder::default()
                    .domain_id("d")
                    .name("n")
                    .build()
                    .unwrap()
            )
            .await
            .unwrap(),
            vec![]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."domain_id" = $1 AND "group"."name" = $2"#,
                ["d".into(), "n".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![]])
            .into_connection();
        let config = Config::default();

        assert_eq!(
            get(&config, &db, "id").await.unwrap(),
            Some(Group {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "group".into(),
                description: Some("fake".into()),
                extra: Some(json!({"foo": "bar"}))
            })
        );
        assert!(get(&config, &db, "missing").await.unwrap().is_none());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."id" = $1 LIMIT $2"#,
                    ["id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."id" = $1 LIMIT $2"#,
                    ["missing".into(), 1u64.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![]])
            .into_connection();
        let config = Config::default();

        let req = GroupCreate {
            id: Some("1".into()),
            domain_id: "foo_domain".into(),
            name: "group".into(),
            description: Some("fake".into()),
            extra: Some(json!({"foo": "bar"})),
        };
        assert_eq!(
            create(&config, &db, req).await.unwrap(),
            get_group_mock("1").into()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "group" ("id", "domain_id", "name", "description", "extra") VALUES ($1, $2, $3, $4, $5) RETURNING "id", "domain_id", "name", "description", "extra""#,
                [
                    "1".into(),
                    "foo_domain".into(),
                    "group".into(),
                    "fake".into(),
                    "{\"foo\":\"bar\"}".into()
                ]
            ),]
        );
    }

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
                r#"DELETE FROM "group" WHERE "group"."id" = $1"#,
                ["id".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_for_user() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![], vec![get_group_mock("1"), get_group_mock("2")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(list_for_user(&config, &db, "foo").await.unwrap(), vec![]);

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
