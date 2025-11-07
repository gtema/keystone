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

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use serde_json::Value;
use tracing::error;

use super::super::types::*;
use crate::config::Config;
use crate::db::entity::{prelude::Project as DbProject, project as db_project};
use crate::resource::ResourceProviderError;
use crate::resource::backends::error::{ResourceDatabaseError, db_err};

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl ResourceBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Get single domain by ID
    async fn get_domain<'a>(
        &self,
        db: &DatabaseConnection,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(get_domain_by_id(&self.config, db, domain_id).await?)
    }

    /// Get single domain by Name
    async fn get_domain_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(get_domain_by_name(&self.config, db, domain_name).await?)
    }

    /// Get single project by ID
    async fn get_project<'a>(
        &self,
        db: &DatabaseConnection,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(get_project(&self.config, db, project_id).await?)
    }

    /// Get single project by Name and Domain ID
    async fn get_project_by_name<'a>(
        &self,
        db: &DatabaseConnection,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(get_project_by_name(&self.config, db, name, domain_id).await?)
    }
}

pub async fn get_domain_by_id<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<Option<Domain>, ResourceDatabaseError> {
    let domain_select =
        DbProject::find_by_id(domain_id.as_ref()).filter(db_project::Column::IsDomain.eq(true));

    let domain_entry: Option<db_project::Model> = domain_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching domain by id"))?;
    domain_entry.map(TryInto::try_into).transpose()
}

pub async fn get_domain_by_name<N: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    domain_name: N,
) -> Result<Option<Domain>, ResourceDatabaseError> {
    let domain_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(true))
        .filter(db_project::Column::Name.eq(domain_name.as_ref()));

    let domain_entry: Option<db_project::Model> = domain_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching domain by name"))?;
    domain_entry.map(TryInto::try_into).transpose()
}

pub async fn get_project<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Project>, ResourceDatabaseError> {
    let project_select =
        DbProject::find_by_id(id.as_ref()).filter(db_project::Column::IsDomain.eq(false));

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching project by id"))?;
    project_entry.map(TryInto::try_into).transpose()
}

pub async fn get_project_by_name<N: AsRef<str>, D: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    name: N,
    domain_id: D,
) -> Result<Option<Project>, ResourceDatabaseError> {
    let project_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(false))
        .filter(db_project::Column::Name.eq(name.as_ref()))
        .filter(db_project::Column::DomainId.eq(domain_id.as_ref()));

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching project by name and domain"))?;
    project_entry.map(TryInto::try_into).transpose()
}

impl TryFrom<db_project::Model> for Project {
    type Error = ResourceDatabaseError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut project_builder = ProjectBuilder::default();
        project_builder.id(value.id.clone());
        project_builder.name(value.name.clone());
        project_builder.domain_id(value.domain_id.clone());
        if let Some(description) = &value.description {
            project_builder.description(description.clone());
        }
        project_builder.enabled(value.enabled.unwrap_or(false));
        if let Some(extra) = &value.extra {
            project_builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize project extra properties: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(project_builder.build()?)
    }
}

impl TryFrom<db_project::Model> for Domain {
    type Error = ResourceDatabaseError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut domain_builder = DomainBuilder::default();
        domain_builder.id(value.id.clone());
        domain_builder.name(value.name.clone());
        if let Some(description) = &value.description {
            domain_builder.description(description.clone());
        }
        domain_builder.enabled(value.enabled.unwrap_or(false));
        if let Some(extra) = &value.extra {
            domain_builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize domain extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(domain_builder.build()?)
    }
}

//#[cfg(test)]
//mod tests {
//    #![allow(clippy::derivable_impls)]
//    use chrono::Local;
//    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
//
//    use crate::db::entity::{local_user, password, user, user_option};
//    use crate::identity::Config;
//
//    use super::*;
//
//    fn get_user_mock(user_id: String) -> user::Model {
//        user::Model {
//            id: user_id.clone(),
//            domain_id: "foo_domain".into(),
//            enabled: Some(true),
//            ..Default::default()
//        }
//    }
//
//    fn get_local_user_with_password_mock(
//        user_id: String,
//        cnt_password: usize,
//    ) -> Vec<(local_user::Model, password::Model)> {
//        let lu = local_user::Model {
//            user_id: user_id.clone(),
//            domain_id: "foo_domain".into(),
//            name: "Apple Cake".to_owned(),
//            ..Default::default()
//        };
//        let mut passwords: Vec<password::Model> = Vec::new();
//        for i in 0..cnt_password {
//            passwords.push(password::Model {
//                id: i as i32,
//                local_user_id: 1,
//                expires_at: None,
//                self_service: false,
//                password_hash: None,
//                created_at: Local::now().naive_utc(),
//                created_at_int: 12345,
//                expires_at_int: None,
//            });
//        }
//        passwords
//            .into_iter()
//            .map(|x| (lu.clone(), x.clone()))
//            .collect()
//    }
//
//    #[tokio::test]
//    async fn test_get_user_local() {
//        // Create MockDatabase with mock query results
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([
//                // First query result - select user itself
//                vec![get_user_mock("1".into())],
//            ])
//            .append_query_results([
//                //// Second query result - user options
//                vec![user_option::Model {
//                    user_id: "1".into(),
//                    option_id: "1000".into(),
//                    option_value: Some("true".into()),
//                }],
//            ])
//            .append_query_results([
//                // Third query result - local user with passwords
//                get_local_user_with_password_mock("1".into(), 1),
//            ])
//            .into_connection();
//        let config = Config::default();
//        assert_eq!(
//            get_user(&config, &db, "1".into()).await.unwrap().unwrap(),
//            User {
//                id: "1".into(),
//                domain_id: "foo_domain".into(),
//                name: "Apple Cake".to_owned(),
//                enabled: true,
//                options: UserOptions {
//                    ignore_change_password_upon_first_use: Some(true),
//                    ..Default::default()
//                },
//                ..Default::default()
//            }
//        );
//
//        // Checking transaction log
//        assert_eq!(
//            db.into_transaction_log(),
//            [
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "user"."id", "user"."extra", "user"."enabled", "user"."default_project_id", "user"."created_at", "user"."last_active_at", "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
//                    ["1".into(), 1u64.into()]
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" INNER JOIN "user" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" = $1"#,
//                    ["1".into()]
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC"#,
//                    ["1".into()]
//                ),
//            ]
//        );
//    }
//}
