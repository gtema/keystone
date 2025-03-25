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

use crate::catalog::backends::error::CatalogDatabaseError;
use crate::catalog::types::*;
use crate::config::Config;
use crate::db::entity::{endpoint as db_endpoint, prelude::Endpoint as DbEndpoint};

pub async fn get<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Endpoint>, CatalogDatabaseError> {
    let select = DbEndpoint::find_by_id(id.as_ref());

    let entry: Option<db_endpoint::Model> = select.one(db).await?;
    entry.map(TryInto::try_into).transpose()
}

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &EndpointListParameters,
) -> Result<Vec<Endpoint>, CatalogDatabaseError> {
    let mut select = DbEndpoint::find();

    if let Some(val) = &params.interface {
        select = select.filter(db_endpoint::Column::Interface.eq(val));
    }
    if let Some(val) = &params.service_id {
        select = select.filter(db_endpoint::Column::ServiceId.eq(val));
    }
    if let Some(val) = &params.region_id {
        select = select.filter(db_endpoint::Column::RegionId.eq(val));
    }

    let db_entities: Vec<db_endpoint::Model> = select.all(db).await?;
    let results: Result<Vec<Endpoint>, _> = db_entities
        .into_iter()
        .map(TryInto::<Endpoint>::try_into)
        .collect();

    results
}

impl TryFrom<db_endpoint::Model> for Endpoint {
    type Error = CatalogDatabaseError;

    fn try_from(value: db_endpoint::Model) -> Result<Self, Self::Error> {
        let mut builder = EndpointBuilder::default();
        builder.id(value.id.clone());
        builder.interface(value.interface.clone());
        builder.service_id(value.service_id.clone());
        builder.url(value.url.clone());
        builder.enabled(value.enabled);
        if let Some(val) = &value.region_id {
            builder.region_id(val);
        }
        if let Some(extra) = &value.extra {
            let extra = serde_json::from_str::<Value>(extra).unwrap();
            builder.extra(extra);
        }

        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::endpoint;

    use super::*;

    fn get_endpoint_mock(id: String) -> endpoint::Model {
        endpoint::Model {
            id: id.clone(),
            interface: "public".into(),
            service_id: "srv_id".into(),
            region_id: Some("region".into()),
            url: "http://localhost".into(),
            enabled: true,
            extra: None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_endpoint_mock("1".into())],
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            Endpoint {
                id: "1".into(),
                interface: "public".into(),
                service_id: "srv_id".into(),
                region_id: Some("region".into()),
                enabled: true,
                url: "http://localhost".into(),
                extra: None
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint" WHERE "endpoint"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_endpoint_mock("1".into())]])
            .append_query_results([vec![get_endpoint_mock("1".into())]])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &EndpointListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
                &db,
                &EndpointListParameters {
                    interface: Some("public".into()),
                    service_id: Some("service_id".into()),
                    region_id: Some("region_id".into())
                }
            )
            .await
            .unwrap(),
            vec![Endpoint {
                id: "1".into(),
                interface: "public".into(),
                service_id: "srv_id".into(),
                region_id: Some("region".into()),
                enabled: true,
                url: "http://localhost".into(),
                extra: None
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint" WHERE "endpoint"."interface" = $1 AND "endpoint"."service_id" = $2 AND "endpoint"."region_id" = $3"#,
                    ["public".into(), "service_id".into(), "region_id".into()]
                ),
            ]
        );
    }
}
