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

use crate::config::Config;
use crate::db::entity::{
    federated_identity_provider as db_federated_identity_provider,
    federation_protocol as db_old_federation_protocol,
    identity_provider as db_old_identity_provider,
    prelude::{
        FederatedIdentityProvider as DbFederatedIdentityProvider,
        IdentityProvider as DbIdentityProvider,
    },
};
use crate::federation::backends::error::FederationDatabaseError;
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<IdentityProvider>, FederationDatabaseError> {
    let select = DbFederatedIdentityProvider::find_by_id(id.as_ref());

    let entry: Option<db_federated_identity_provider::Model> = select.one(db).await?;
    entry.map(TryInto::try_into).transpose()
}

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &IdentityProviderListParameters,
) -> Result<Vec<IdentityProvider>, FederationDatabaseError> {
    let mut select = DbFederatedIdentityProvider::find();

    if let Some(val) = &params.name {
        select = select.filter(db_federated_identity_provider::Column::Name.eq(val));
    }

    if let Some(val) = &params.domain_id {
        select = select.filter(db_federated_identity_provider::Column::DomainId.eq(val));
    }

    let db_entities: Vec<db_federated_identity_provider::Model> = select.all(db).await?;
    let results: Result<Vec<IdentityProvider>, _> = db_entities
        .into_iter()
        .map(TryInto::<IdentityProvider>::try_into)
        .collect();

    results
}

pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    idp: IdentityProvider,
) -> Result<IdentityProvider, FederationDatabaseError> {
    let entry = db_federated_identity_provider::ActiveModel {
        id: Set(idp.id.clone()),
        domain_id: Set(idp.domain_id.clone()),
        name: Set(idp.name.clone()),
        oidc_discovery_url: idp
            .oidc_discovery_url
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_client_id: idp.oidc_client_id.clone().map(Set).unwrap_or(NotSet).into(),
        oidc_client_secret: idp
            .oidc_client_secret
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_response_mode: idp
            .oidc_response_mode
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_response_types: idp
            .oidc_response_types
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        jwks_url: idp.jwks_url.clone().map(Set).unwrap_or(NotSet).into(),
        jwt_validation_pubkeys: idp
            .jwt_validation_pubkeys
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        bound_issuer: idp.bound_issuer.clone().map(Set).unwrap_or(NotSet).into(),
        default_mapping_name: idp
            .default_mapping_name
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        provider_config: idp
            .provider_config
            .clone()
            .map(|x| Set(Some(x)))
            .unwrap_or(NotSet),
    };

    let db_entry: db_federated_identity_provider::Model = entry.insert(db).await?;

    // For compatibility reasons add entry for the IDP old-style as well as the protocol to keep
    // constraints working
    db_old_identity_provider::ActiveModel {
        id: Set(idp.id.clone()),
        enabled: Set(false),
        description: Set(Some(idp.name.clone())),
        domain_id: Set(idp.domain_id.clone().unwrap_or("<<null>>".into())),
        authorization_ttl: NotSet,
    }
    .insert(db)
    .await?;

    db_old_federation_protocol::ActiveModel {
        id: Set("oidc".into()),
        idp_id: Set(idp.id.clone()),
        mapping_id: Set("<<null>>".into()),
        remote_id_attribute: NotSet,
    }
    .insert(db)
    .await?;

    db_old_federation_protocol::ActiveModel {
        id: Set("jwt".into()),
        idp_id: Set(idp.id.clone()),
        mapping_id: Set("<<null>>".into()),
        remote_id_attribute: NotSet,
    }
    .insert(db)
    .await?;

    db_entry.try_into()
}

pub async fn update<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
    idp: IdentityProviderUpdate,
) -> Result<IdentityProvider, FederationDatabaseError> {
    if let Some(current) = DbFederatedIdentityProvider::find_by_id(id.as_ref())
        .one(db)
        .await?
    {
        let mut entry: db_federated_identity_provider::ActiveModel = current.into();
        if let Some(val) = idp.name {
            entry.name = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_discovery_url {
            entry.oidc_discovery_url = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_client_id {
            entry.oidc_client_id = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_client_secret {
            entry.oidc_client_secret = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_response_mode {
            entry.oidc_response_mode = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_response_types {
            entry.oidc_response_types = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = idp.jwks_url {
            entry.jwks_url = Set(val.to_owned());
        }
        if let Some(val) = idp.jwt_validation_pubkeys {
            entry.jwt_validation_pubkeys = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = idp.bound_issuer {
            entry.bound_issuer = Set(val.to_owned());
        }
        if let Some(val) = idp.provider_config {
            entry.provider_config = Set(val.to_owned());
        }
        if let Some(val) = idp.default_mapping_name {
            entry.default_mapping_name = Set(val.to_owned());
        }

        let db_entry: db_federated_identity_provider::Model = entry.update(db).await?;
        db_entry.try_into()
    } else {
        Err(FederationDatabaseError::IdentityProviderNotFound(
            id.as_ref().to_string(),
        ))
    }
}

pub async fn delete<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
) -> Result<(), FederationDatabaseError> {
    let res = DbFederatedIdentityProvider::delete_by_id(id.as_ref())
        .exec(db)
        .await?;
    if res.rows_affected == 1 {
        DbIdentityProvider::delete_by_id(id.as_ref())
            .exec(db)
            .await?;
        Ok(())
    } else {
        Err(FederationDatabaseError::IdentityProviderNotFound(
            id.as_ref().to_string(),
        ))
    }
}

impl TryFrom<db_federated_identity_provider::Model> for IdentityProvider {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_identity_provider::Model) -> Result<Self, Self::Error> {
        let mut builder = IdentityProviderBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        if let Some(val) = &value.domain_id {
            builder.domain_id(val);
        }
        if let Some(val) = &value.oidc_discovery_url {
            builder.oidc_discovery_url(val);
        }
        if let Some(val) = &value.oidc_client_id {
            builder.oidc_client_id(val);
        }
        if let Some(val) = &value.oidc_client_secret {
            builder.oidc_client_secret(val);
        }
        if let Some(val) = &value.oidc_response_mode {
            builder.oidc_response_mode(val);
        }
        if let Some(val) = &value.oidc_response_types {
            if !val.is_empty() {
                builder.oidc_response_types(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        if let Some(val) = &value.jwks_url {
            builder.jwks_url(val);
        }
        if let Some(val) = &value.jwt_validation_pubkeys {
            if !val.is_empty() {
                builder.jwt_validation_pubkeys(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        if let Some(val) = &value.bound_issuer {
            builder.bound_issuer(val);
        }
        if let Some(val) = &value.provider_config {
            builder.provider_config(val.clone());
        }
        if let Some(val) = &value.default_mapping_name {
            builder.default_mapping_name(val.clone());
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use crate::config::Config;
    use crate::db::entity::{federated_identity_provider, federation_protocol, identity_provider};

    use super::*;

    fn get_idp_mock<S: AsRef<str>>(id: S) -> federated_identity_provider::Model {
        federated_identity_provider::Model {
            id: id.as_ref().into(),
            name: "name".into(),
            domain_id: Some("did".into()),
            ..Default::default()
        }
    }

    fn get_old_idp_mock<S: AsRef<str>>(id: S) -> identity_provider::Model {
        identity_provider::Model {
            id: id.as_ref().into(),
            enabled: true,
            description: Some("name".into()),
            domain_id: "did".into(),
            authorization_ttl: None,
        }
    }

    fn get_old_proto_mock<S: AsRef<str>>(id: S) -> federation_protocol::Model {
        federation_protocol::Model {
            id: "oidc".into(),
            idp_id: id.as_ref().into(),
            mapping_id: "<<null>>".into(),
            remote_id_attribute: None,
        }
    }

    #[test]
    fn test_from_db_model() {}

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            IdentityProvider {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &IdentityProviderListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
                &db,
                &IdentityProviderListParameters {
                    name: Some("idp_name".into()),
                    domain_id: Some("did".into()),
                }
            )
            .await
            .unwrap(),
            vec![IdentityProvider {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."name" = $1 AND "federated_identity_provider"."domain_id" = $2"#,
                    ["idp_name".into(), "did".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .append_query_results([vec![get_old_idp_mock("1")]])
            .append_query_results([vec![get_old_proto_mock("1")]])
            .append_query_results([vec![get_old_proto_mock("2")]])
            .into_connection();
        let config = Config::default();

        let req = IdentityProvider {
            id: "1".into(),
            name: "idp".into(),
            domain_id: Some("foo_domain".into()),
            oidc_discovery_url: Some("url".into()),
            oidc_client_id: Some("oidccid".into()),
            oidc_client_secret: Some("oidccs".into()),
            oidc_response_mode: Some("oidcrm".into()),
            oidc_response_types: Some(vec!["t1".into(), "t2".into()]),
            jwks_url: Some("http://jwks".into()),
            jwt_validation_pubkeys: Some(vec!["jt1".into(), "jt2".into()]),
            bound_issuer: Some("bi".into()),
            default_mapping_name: Some("dummy".into()),
            provider_config: Some(json!({"foo": "bar"})),
        };

        assert_eq!(
            create(&config, &db, req).await.unwrap(),
            get_idp_mock("1").try_into().unwrap()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federated_identity_provider" ("id", "name", "domain_id", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING "id", "name", "domain_id", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config""#,
                    [
                        "1".into(),
                        "idp".into(),
                        "foo_domain".into(),
                        "url".into(),
                        "oidccid".into(),
                        "oidccs".into(),
                        "oidcrm".into(),
                        "t1,t2".into(),
                        "http://jwks".into(),
                        "jt1,jt2".into(),
                        "bi".into(),
                        "dummy".into(),
                        json!({"foo": "bar"}).into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "identity_provider" ("id", "enabled", "description", "domain_id") VALUES ($1, $2, $3, $4) RETURNING "id", "enabled", "description", "domain_id", "authorization_ttl""#,
                    ["1".into(), false.into(), "idp".into(), "foo_domain".into(),]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federation_protocol" ("id", "idp_id", "mapping_id") VALUES ($1, $2, $3) RETURNING "id", "idp_id", "mapping_id", "remote_id_attribute""#,
                    ["oidc".into(), "1".into(), "<<null>>".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federation_protocol" ("id", "idp_id", "mapping_id") VALUES ($1, $2, $3) RETURNING "id", "idp_id", "mapping_id", "remote_id_attribute""#,
                    ["jwt".into(), "1".into(), "<<null>>".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_update() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")], vec![get_idp_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        let req = IdentityProviderUpdate {
            name: Some("idp".into()),
            oidc_discovery_url: Some(Some("url".into())),
            oidc_client_id: Some(Some("oidccid".into())),
            oidc_client_secret: Some(Some("oidccs".into())),
            oidc_response_mode: Some(Some("oidcrm".into())),
            oidc_response_types: Some(Some(vec!["t1".into(), "t2".into()])),
            jwks_url: Some(Some("http://jwks".into())),
            jwt_validation_pubkeys: Some(Some(vec!["jt1".into(), "jt2".into()])),
            bound_issuer: Some(Some("bi".into())),
            default_mapping_name: Some(Some("dummy".into())),
            provider_config: Some(Some(json!({"foo": "bar"}))),
        };

        assert_eq!(
            update(&config, &db, "1", req).await.unwrap(),
            get_idp_mock("1").try_into().unwrap()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "federated_identity_provider" SET "name" = $1, "oidc_discovery_url" = $2, "oidc_client_id" = $3, "oidc_client_secret" = $4, "oidc_response_mode" = $5, "oidc_response_types" = $6, "jwks_url" = $7, "jwt_validation_pubkeys" = $8, "bound_issuer" = $9, "default_mapping_name" = $10, "provider_config" = $11 WHERE "federated_identity_provider"."id" = $12 RETURNING "id", "name", "domain_id", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config""#,
                    [
                        "idp".into(),
                        "url".into(),
                        "oidccid".into(),
                        "oidccs".into(),
                        "oidcrm".into(),
                        "t1,t2".into(),
                        "http://jwks".into(),
                        "jt1,jt2".into(),
                        "bi".into(),
                        "dummy".into(),
                        json!({"foo": "bar"}).into(),
                        "1".into(),
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_delete() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .into_connection();
        let config = Config::default();

        delete(&config, &db, "id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "federated_identity_provider" WHERE "federated_identity_provider"."id" = $1"#,
                    ["id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "identity_provider" WHERE "identity_provider"."id" = $1"#,
                    ["id".into()]
                ),
            ]
        );
    }
}
