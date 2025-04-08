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
use sea_orm::prelude::Expr;
use sea_orm::query::*;
use std::collections::{BTreeMap, HashMap};

use crate::assignment::backends::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::config::Config;
use crate::db::entity::{
    assignment as db_assignment,
    prelude::{Assignment as DbAssignment, Role as DbRole},
    role as db_role,
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
    if let Some(val) = &params.user_id {
        select = select.filter(db_assignment::Column::ActorId.eq(val));
    } else if let Some(val) = &params.group_id {
        select = select.filter(db_assignment::Column::ActorId.eq(val));
    }
    if let Some(val) = &params.project_id {
        select = select.filter(db_assignment::Column::TargetId.eq(val));
    } else if let Some(val) = &params.domain_id {
        select = select.filter(db_assignment::Column::TargetId.eq(val));
    }

    let db_entities: Vec<db_assignment::Model> = select.all(db).await?;
    let results: Result<Vec<Assignment>, _> = db_entities
        .into_iter()
        .map(TryInto::<Assignment>::try_into)
        .collect();

    results
}

/// Get all role assignments by list of actors on list of targets.
///
/// It is a naive interpretation of the effective role assignments where we check all roles
/// assigned to the user (including groups) on a concrete target (including all higher targets the
/// role can be inherited from)
pub async fn list_for_multiple_actors_and_targets(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &RoleAssignmentListForMultipleActorTargetParameters,
) -> Result<Vec<Assignment>, AssignmentDatabaseError> {
    let mut select = DbAssignment::find();

    if !params.actors.is_empty() {
        select = select.filter(db_assignment::Column::ActorId.is_in(params.actors.clone()));
    }
    if let Some(rid) = &params.role_id {
        select = select.filter(db_assignment::Column::RoleId.eq(rid));
    }
    if !params.targets.is_empty() {
        let mut cond = Condition::any();
        for target in params.targets.iter() {
            cond = cond.add(
                Condition::all()
                    .add(db_assignment::Column::TargetId.eq(&target.target_id))
                    .add_option(
                        target
                            .inherited
                            .map(|x| db_assignment::Column::Inherited.eq(x)),
                    ),
            );
        }
        select = select.filter(cond);
    }

    // Get all implied rules
    let imply_rules = super::implied_role::list_rules(db, true).await?;

    let mut db_assignments: BTreeMap<String, db_assignment::Model> = BTreeMap::new();
    // Get assignments resolving the roles inference
    for assignment in select.all(db).await? {
        db_assignments.insert(assignment.role_id.clone(), assignment.clone());
        if let Some(implies) = imply_rules.get(&assignment.role_id) {
            let mut implied_assignment = assignment.clone();
            for implied in implies.iter() {
                implied_assignment.role_id = implied.clone();
                db_assignments.insert(implied.clone(), implied_assignment.clone());
            }
        }
    }

    if !db_assignments.is_empty() {
        // Get roles for the found IDs
        let roles: HashMap<String, String> = HashMap::from_iter(
            DbRole::find()
                .select_only()
                .columns([db_role::Column::Id, db_role::Column::Name])
                .filter(Expr::col(db_role::Column::Id).is_in(db_assignments.keys()))
                .into_tuple()
                .all(db)
                .await?,
        );
        let results: Result<Vec<Assignment>, _> = db_assignments
            .values()
            .map(|item| TryInto::<Assignment>::try_into((item, roles.get(&item.role_id))))
            .collect();
        results
    } else {
        Ok(Vec::new())
    }
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

impl TryFrom<&db_assignment::Model> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: &db_assignment::Model) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.role_id.clone());
        builder.actor_id(value.actor_id.clone());
        builder.target_id(value.target_id.clone());
        builder.inherited(value.inherited);
        builder.r#type(value.r#type.clone());

        Ok(builder.build()?)
    }
}

impl TryFrom<(&db_assignment::Model, Option<&String>)> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: (&db_assignment::Model, Option<&String>)) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.0.role_id.clone());
        builder.actor_id(value.0.actor_id.clone());
        builder.target_id(value.0.target_id.clone());
        builder.inherited(value.0.inherited);
        builder.r#type(value.0.r#type.clone());
        if let Some(val) = value.1 {
            builder.role_name(val.clone());
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<(db_assignment::Model, Option<db_role::Model>)> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(
        value: (db_assignment::Model, Option<db_role::Model>),
    ) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.0.role_id.clone());
        builder.actor_id(value.0.actor_id.clone());
        builder.target_id(value.0.target_id.clone());
        builder.inherited(value.0.inherited);
        builder.r#type(value.0.r#type);
        if let Some(val) = &value.1 {
            builder.role_name(val.name.clone());
        }

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
    use std::collections::BTreeMap;

    use crate::config::Config;
    use crate::db::entity::{assignment, implied_role, role, sea_orm_active_enums};

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

    fn get_role_mock(role_id: String, role_name: String) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("id".to_string(), Value::String(Some(Box::new(role_id)))),
            ("name".to_string(), Value::String(Some(Box::new(role_name)))),
        ])
    }

    fn get_implied_rules_mock() -> Vec<implied_role::Model> {
        vec![implied_role::Model {
            prior_role_id: "1".to_string(),
            implied_role_id: "2".to_string(),
        }]
    }

    fn get_role_assignment_with_role_mock(role_id: String) -> (assignment::Model, role::Model) {
        (
            assignment::Model {
                role_id: role_id.clone(),
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: sea_orm_active_enums::Type::UserProject,
                inherited: false,
            },
            role::Model {
                id: role_id.clone(),
                name: role_id.clone(),
                extra: None,
                domain_id: String::new(),
                description: None,
            },
        )
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
                role_name: None,
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
                    group_id: Some("actor".into()),
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
                    user_id: Some("actor".into()),
                    project_id: Some("target".into()),
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

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_actors_single_target() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![
                get_role_mock("1".into(), "rname".into()),
                get_role_mock("2".into(), "rname2".into()),
            ]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                    targets: vec![RoleAssignmentTarget {
                        target_id: "pid1".into(),
                        inherited: None
                    }],
                    role_id: Some("rid".into())
                }
            )
            .await
            .unwrap(),
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("rname".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
                Assignment {
                    role_id: "2".into(),
                    role_name: Some("rname2".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."actor_id" IN ($1, $2, $3) AND "assignment"."role_id" = $4 AND "assignment"."target_id" = $5"#,
                    [
                        "uid1".into(),
                        "gid1".into(),
                        "gid2".into(),
                        "rid".into(),
                        "pid1".into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_complex_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![
                get_role_mock("1".into(), "rname".into()),
                get_role_mock("2".into(), "rname2".into()),
            ]])
            .into_connection();
        let config = Config::default();
        // multiple actors multiple complex targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: None
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
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
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."actor_id" IN ($1, $2, $3) AND ("assignment"."target_id" = $4 OR ("assignment"."target_id" = $5 AND "assignment"."inherited" = $6))"#,
                    [
                        "uid1".into(),
                        "gid1".into(),
                        "gid2".into(),
                        "pid1".into(),
                        "pid2".into(),
                        true.into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_empty_actors_and_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![
                get_role_mock("1".into(), "rname".into()),
                get_role_mock("2".into(), "rname2".into()),
            ]])
            .into_connection();
        let config = Config::default();
        //// empty actors and targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![],
                    role_id: None
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
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_mixed_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1".into())]])
            .append_query_results([vec![
                get_role_mock("1".into(), "rname".into()),
                get_role_mock("2".into(), "rname2".into()),
            ]])
            .into_connection();
        let config = Config::default();

        //// only mixed targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: None
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
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
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."target_id" = $1 OR ("assignment"."target_id" = $2 AND "assignment"."inherited" = $3)"#,
                    ["pid1".into(), "pid2".into(), true.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_complex_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([Vec::<assignment::Model>::new()])
            .into_connection();
        let config = Config::default();

        //// only complex targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: Some(false)
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
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
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS text), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE ("assignment"."target_id" = $1 AND "assignment"."inherited" = $2) OR ("assignment"."target_id" = $3 AND "assignment"."inherited" = $4)"#,
                    ["pid1".into(), false.into(), "pid2".into(), true.into()]
                ),
            ]
        );
    }
}
