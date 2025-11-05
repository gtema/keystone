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

use crate::catalog::backends::error::{CatalogDatabaseError, db_err};
use crate::catalog::types::*;
use crate::config::Config;
use crate::db::entity::{prelude::Service as DbService, service as db_service};

pub async fn get<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Service>, CatalogDatabaseError> {
    let select = DbService::find_by_id(id.as_ref());

    let entry: Option<db_service::Model> = select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching service by ID"))?;
    entry.map(TryInto::try_into).transpose()
}

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &ServiceListParameters,
) -> Result<Vec<Service>, CatalogDatabaseError> {
    let mut select = DbService::find();

    if let Some(typ) = &params.r#type {
        select = select.filter(db_service::Column::Type.eq(typ));
    }

    let db_services: Vec<db_service::Model> = select
        .all(db)
        .await
        .map_err(|err| db_err(err, "fetching services"))?;
    let results: Result<Vec<Service>, _> = db_services
        .into_iter()
        .map(TryInto::<Service>::try_into)
        .collect();

    results
}

impl TryFrom<db_service::Model> for Service {
    type Error = CatalogDatabaseError;

    fn try_from(value: db_service::Model) -> Result<Self, Self::Error> {
        let mut builder = ServiceBuilder::default();
        builder.id(value.id.clone());
        if let Some(typ) = &value.r#type {
            builder.r#type(typ);
        }
        builder.enabled(value.enabled);
        if let Some(extra) = &value.extra {
            let extra = serde_json::from_str::<Value>(extra).unwrap();
            if let Some(name) = extra.get("name").and_then(|x| x.as_str()) {
                builder.name(name);
            }
            builder.extra(extra);
        }

        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use crate::config::Config;
    use crate::db::entity::service;

    use super::*;

    fn get_service_mock(id: String) -> service::Model {
        service::Model {
            id: id.clone(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name": "srv"}"#.to_string()),
        }
    }

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_service_mock("1".into())],
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            Service {
                id: "1".into(),
                r#type: Some("type".into()),
                enabled: true,
                name: Some("srv".into()),
                extra: Some(json!({"name": "srv"})),
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" WHERE "service"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_service_mock("1".into())]])
            .append_query_results([vec![get_service_mock("1".into())]])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &ServiceListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
                &db,
                &ServiceListParameters {
                    r#type: Some("type".into()),
                    name: Some("service_name".into())
                }
            )
            .await
            .unwrap(),
            vec![Service {
                id: "1".into(),
                r#type: Some("type".into()),
                enabled: true,
                name: Some("srv".into()),
                extra: Some(json!({"name": "srv"})),
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" WHERE "service"."type" = $1"#,
                    ["type".into()]
                ),
            ]
        );
    }
}
