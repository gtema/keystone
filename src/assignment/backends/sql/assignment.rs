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

use crate::assignment::backends::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::config::Config;
use crate::db::entity::{
    assignment as db_assignment, prelude::Assignment as DbAssignment,
    sea_orm_active_enums::Type as DbAssignmentType,
};

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &RoleAssignmentListParameters,
) -> Result<Vec<Assignment>, AssignmentDatabaseError> {
    let mut select = DbAssignment::find();

    if let Some(val) = &params.role_id {
        select = select.filter(db_assignment::Column::RoleId.eq(val));
    }
    if let Some(val) = &params.actor_id {
        select = select.filter(db_assignment::Column::ActorId.eq(val));
    }
    if let Some(val) = &params.target_id {
        select = select.filter(db_assignment::Column::TargetId.eq(val));
    }

    let db_entities: Vec<db_assignment::Model> = select.all(db).await?;
    let results: Result<Vec<Assignment>, _> = db_entities
        .into_iter()
        .map(TryInto::<Assignment>::try_into)
        .collect();

    results
}

impl TryFrom<db_assignment::Model> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: db_assignment::Model) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.role_id.clone());
        builder.actor_id(value.actor_id.clone());
        builder.target_id(value.target_id.clone());
        builder.inherited(value.inherited);
        builder.r#type(value.r#type);

        Ok(builder.build()?)
    }
}

impl From<DbAssignmentType> for AssignmentType {
    fn from(value: DbAssignmentType) -> Self {
        match value {
            DbAssignmentType::GroupDomain => Self::GroupDomain,
            DbAssignmentType::GroupProject => Self::GroupProject,
            DbAssignmentType::UserDomain => Self::UserDomain,
            DbAssignmentType::UserProject => Self::UserProject,
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::{assignment, sea_orm_active_enums};

    use super::*;

    fn get_role_assignment_mock(role_id: String) -> assignment::Model {
        assignment::Model {
            role_id: role_id.clone(),
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: sea_orm_active_enums::Type::UserProject,
            inherited: false,
        }
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(&config, &db, &RoleAssignmentListParameters::default())
                .await
                .unwrap(),
            vec![Assignment {
                role_id: "1".into(),
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
            }]
        );
        assert!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    role_id: Some("foo".into()),
                    ..Default::default()
                }
            )
            .await
            .is_ok()
        );
        assert!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    role_id: Some("foo".into()),
                    actor_id: Some("actor".into()),
                    ..Default::default()
                }
            )
            .await
            .is_ok()
        );
        assert!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    role_id: Some("foo".into()),
                    actor_id: Some("actor".into()),
                    target_id: Some("target".into()),
                    ..Default::default()
                }
            )
            .await
            .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1"#,
                    ["foo".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."actor_id" = $2"#,
                    ["foo".into(), "actor".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."actor_id" = $2 AND "assignment"."target_id" = $3"#,
                    ["foo".into(), "actor".into(), "target".into()]
                ),
            ]
        );
    }
}
