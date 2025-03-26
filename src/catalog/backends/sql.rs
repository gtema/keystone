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

use super::super::types::*;
use crate::catalog::CatalogProviderError;
use crate::catalog::backends::error::CatalogDatabaseError;
use crate::config::Config;
use crate::db::entity::{
    endpoint as db_endpoint,
    prelude::{Endpoint as DbEndpoint, Service as DbService},
    service as db_service,
};

mod endpoint;
mod service;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl CatalogBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// List Services
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list_services(
        &self,
        db: &DatabaseConnection,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError> {
        Ok(service::list(&self.config, db, params).await?)
    }

    /// Get single service by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_service<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        Ok(service::get(&self.config, db, id).await?)
    }

    /// List Endpoints
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list_endpoints(
        &self,
        db: &DatabaseConnection,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        Ok(endpoint::list(&self.config, db, params).await?)
    }

    /// Get single endpoint by ID
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_endpoint<'a>(
        &self,
        db: &DatabaseConnection,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        Ok(endpoint::get(&self.config, db, id).await?)
    }

    /// Get Catalog (Services with Endpoints)
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get_catalog(
        &self,
        db: &DatabaseConnection,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        Ok(get_catalog(db, enabled).await?)
    }
}

async fn get_catalog(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogDatabaseError> {
    let db_entities: Vec<(db_service::Model, Vec<db_endpoint::Model>)> = DbService::find()
        .filter(db_service::Column::Enabled.eq(enabled))
        .find_with_related(DbEndpoint)
        .filter(db_endpoint::Column::Enabled.eq(enabled))
        .all(db)
        .await?;

    let mut res: Vec<(Service, Vec<Endpoint>)> = Vec::new();
    for (srv, db_endpoints) in db_entities.into_iter() {
        let service: Service = srv.try_into()?;
        let endpoints: Result<Vec<Endpoint>, _> = db_endpoints
            .into_iter()
            .map(TryInto::<Endpoint>::try_into)
            .collect();
        res.push((service, endpoints?));
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use crate::db::entity::{endpoint, service};

    use super::*;

    fn get_service_mock(id: String) -> service::Model {
        service::Model {
            id: id.clone(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name": "srv"}"#.to_string()),
        }
    }

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
    async fn test_get_catalog() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                (get_service_mock("1".into()), get_endpoint_mock("1".into())),
                (get_service_mock("1".into()), get_endpoint_mock("2".into())),
            ]])
            .into_connection();
        assert_eq!(
            get_catalog(&db, false).await.unwrap(),
            vec![(
                Service {
                    id: "1".into(),
                    r#type: Some("type".into()),
                    enabled: true,
                    name: Some("srv".into()),
                    extra: Some(json!({"name": "srv"})),
                },
                vec![
                    Endpoint {
                        id: "1".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: None
                    },
                    Endpoint {
                        id: "2".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: None
                    }
                ]
            )]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "service"."id" AS "A_id", "service"."type" AS "A_type", "service"."enabled" AS "A_enabled", "service"."extra" AS "A_extra", "endpoint"."id" AS "B_id", "endpoint"."legacy_endpoint_id" AS "B_legacy_endpoint_id", "endpoint"."interface" AS "B_interface", "endpoint"."service_id" AS "B_service_id", "endpoint"."url" AS "B_url", "endpoint"."extra" AS "B_extra", "endpoint"."enabled" AS "B_enabled", "endpoint"."region_id" AS "B_region_id" FROM "service" LEFT JOIN "endpoint" ON "service"."id" = "endpoint"."service_id" WHERE "service"."enabled" = $1 AND "endpoint"."enabled" = $2 ORDER BY "service"."id" ASC"#,
                [false.into(), false.into()]
            ),]
        );
    }
}
