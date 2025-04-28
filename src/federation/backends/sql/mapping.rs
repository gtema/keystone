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
    federated_mapping as db_federated_mapping, prelude::FederatedMapping as DbFederatedMapping,
};
use crate::federation::backends::error::FederationDatabaseError;
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Mapping>, FederationDatabaseError> {
    let select = DbFederatedMapping::find_by_id(id.as_ref());

    let entry: Option<db_federated_mapping::Model> = select.one(db).await?;
    entry.map(TryInto::try_into).transpose()
}

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &MappingListParameters,
) -> Result<Vec<Mapping>, FederationDatabaseError> {
    let mut select = DbFederatedMapping::find();

    if let Some(val) = &params.name {
        select = select.filter(db_federated_mapping::Column::Name.eq(val));
    }

    if let Some(val) = &params.domain_id {
        select = select.filter(db_federated_mapping::Column::DomainId.eq(val));
    }

    if let Some(val) = &params.idp_id {
        select = select.filter(db_federated_mapping::Column::IdpId.eq(val));
    }

    let db_entities: Vec<db_federated_mapping::Model> = select.all(db).await?;
    let results: Result<Vec<Mapping>, _> = db_entities
        .into_iter()
        .map(TryInto::<Mapping>::try_into)
        .collect();

    results
}

pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    mapping: Mapping,
) -> Result<Mapping, FederationDatabaseError> {
    let entry = db_federated_mapping::ActiveModel {
        id: Set(mapping.id.clone()),
        domain_id: Set(mapping.domain_id.clone()),
        name: Set(mapping.name.clone()),
        idp_id: Set(mapping.idp_id.clone()),
        allowed_redirect_uris: mapping
            .allowed_redirect_uris
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        user_claim: Set(mapping.user_claim.clone()),
        user_claim_json_pointer: mapping
            .user_claim_json_pointer
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        groups_claim: mapping
            .groups_claim
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        bound_audiences: mapping
            .bound_audiences
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        bound_subject: mapping
            .bound_subject
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        bound_claims: mapping
            .bound_claims
            .clone()
            .map(|x| Set(Some(x)))
            .unwrap_or(NotSet),
        oidc_scopes: mapping
            .oidc_scopes
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        claim_mappings: mapping
            .claim_mappings
            .clone()
            .map(|x| Set(Some(x)))
            .unwrap_or(NotSet),
        token_user_id: mapping
            .token_user_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        token_role_ids: mapping
            .token_role_ids
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        token_project_id: mapping
            .token_project_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
    };

    let db_entry: db_federated_mapping::Model = entry.insert(db).await?;

    db_entry.try_into()
}

pub async fn update<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
    mapping: MappingUpdate,
) -> Result<Mapping, FederationDatabaseError> {
    if let Some(current) = DbFederatedMapping::find_by_id(id.as_ref()).one(db).await? {
        let mut entry: db_federated_mapping::ActiveModel = current.into();
        if let Some(val) = mapping.name {
            entry.name = Set(val.to_owned());
        }
        if let Some(val) = mapping.idp_id {
            entry.idp_id = Set(val.to_owned());
        }
        if let Some(val) = mapping.allowed_redirect_uris {
            entry.allowed_redirect_uris = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.user_claim {
            entry.user_claim = Set(val.to_owned());
        }
        if let Some(val) = mapping.user_claim_json_pointer {
            entry.user_claim_json_pointer = Set(val.to_owned());
        }
        if let Some(val) = mapping.groups_claim {
            entry.groups_claim = Set(val.to_owned());
        }
        if let Some(val) = mapping.bound_audiences {
            entry.bound_audiences = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.bound_subject {
            entry.bound_subject = Set(val.to_owned());
        }
        if let Some(val) = &mapping.bound_claims {
            entry.bound_claims = Set(Some(val.clone()));
        }
        if let Some(val) = mapping.oidc_scopes {
            entry.oidc_scopes = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = &mapping.claim_mappings {
            entry.claim_mappings = Set(Some(val.clone()));
        }
        if let Some(val) = mapping.token_user_id {
            entry.token_user_id = Set(val.to_owned());
        }
        if let Some(val) = mapping.token_role_ids {
            entry.token_role_ids = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.token_project_id {
            entry.token_project_id = Set(val.to_owned());
        }

        let db_entry: db_federated_mapping::Model = entry.update(db).await?;
        db_entry.try_into()
    } else {
        Err(FederationDatabaseError::MappingNotFound(
            id.as_ref().to_string(),
        ))
    }
}

pub async fn delete<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
) -> Result<(), FederationDatabaseError> {
    let res = DbFederatedMapping::delete_by_id(id.as_ref())
        .exec(db)
        .await?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(FederationDatabaseError::IdentityProviderNotFound(
            id.as_ref().to_string(),
        ))
    }
}

impl TryFrom<db_federated_mapping::Model> for Mapping {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_mapping::Model) -> Result<Self, Self::Error> {
        let mut builder = MappingBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        builder.idp_id(value.idp_id.clone());
        if let Some(val) = &value.domain_id {
            builder.domain_id(val);
        }
        if let Some(val) = &value.allowed_redirect_uris {
            if !val.is_empty() {
                builder.allowed_redirect_uris(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        builder.user_claim(value.user_claim.clone());
        if let Some(val) = &value.user_claim_json_pointer {
            builder.user_claim_json_pointer(val);
        }
        if let Some(val) = &value.groups_claim {
            builder.groups_claim(val);
        }
        if let Some(val) = &value.bound_audiences {
            if !val.is_empty() {
                builder.bound_audiences(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        if let Some(val) = &value.bound_subject {
            builder.bound_subject(val);
        }
        if let Some(val) = &value.bound_claims {
            builder.bound_claims(val.clone());
        }
        if let Some(val) = &value.oidc_scopes {
            if !val.is_empty() {
                builder.oidc_scopes(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        if let Some(val) = &value.claim_mappings {
            builder.claim_mappings(val.clone());
        }
        if let Some(val) = &value.token_user_id {
            builder.token_user_id(val.clone());
        }
        if let Some(val) = &value.token_role_ids {
            if !val.is_empty() {
                builder.token_role_ids(Vec::from_iter(val.split(",").map(Into::into)));
            }
        }
        if let Some(val) = &value.token_project_id {
            builder.token_project_id(val.clone());
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use crate::config::Config;
    use crate::db::entity::federated_mapping;

    use super::*;

    fn get_mapping_mock<S: AsRef<str>>(id: S) -> federated_mapping::Model {
        federated_mapping::Model {
            id: id.as_ref().into(),
            name: "name".into(),
            domain_id: Some("did".into()),
            idp_id: "idp".into(),
            user_claim: "sub".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            Mapping {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                idp_id: "idp".into(),
                user_claim: "sub".into(),
                ..Default::default()
            }
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &MappingListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
                &db,
                &MappingListParameters {
                    name: Some("mapping_name".into()),
                    domain_id: Some("did".into()),
                    idp_id: Some("idp".into())
                }
            )
            .await
            .unwrap(),
            vec![Mapping {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                idp_id: "idp".into(),
                user_claim: "sub".into(),
                ..Default::default()
            }]
        );

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."name" = $1 AND "federated_mapping"."domain_id" = $2 AND "federated_mapping"."idp_id" = $3"#,
                    ["mapping_name".into(), "did".into(), "idp".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();
        let config = Config::default();

        let req = Mapping {
            id: "1".into(),
            name: "mapping".into(),
            domain_id: Some("foo_domain".into()),
            idp_id: "idp".into(),
            allowed_redirect_uris: Some(vec!["url".into()]),
            user_claim: "sub".into(),
            user_claim_json_pointer: Some(".".into()),
            groups_claim: Some("groups".into()),
            bound_audiences: Some(vec!["a1".into(), "a2".into()]),
            bound_subject: Some("subject".into()),
            bound_claims: Some(json!({"department": "foo"})),
            claim_mappings: Some(json!({"foo": "bar"})),
            oidc_scopes: Some(vec!["oidc".into(), "oauth".into()]),
            token_user_id: Some("uid".into()),
            token_role_ids: Some(vec!["r1".into(), "r2".into()]),
            token_project_id: Some("pid".into()),
        };

        assert_eq!(
            create(&config, &db, req).await.unwrap(),
            get_mapping_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "federated_mapping" ("id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING "id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id""#,
                [
                    "1".into(),
                    "mapping".into(),
                    "idp".into(),
                    "foo_domain".into(),
                    "url".into(),
                    "sub".into(),
                    ".".into(),
                    "groups".into(),
                    "a1,a2".into(),
                    "subject".into(),
                    json!({"department": "foo"}).into(),
                    "oidc,oauth".into(),
                    json!({"foo": "bar"}).into(),
                    "uid".into(),
                    "r1,r2".into(),
                    "pid".into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")], vec![get_mapping_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        let req = MappingUpdate {
            name: Some("name".into()),
            idp_id: Some("idp".into()),
            allowed_redirect_uris: Some(Some(vec!["url".into()])),
            user_claim: Some("sub".into()),
            user_claim_json_pointer: Some(Some(".".into())),
            groups_claim: Some(Some("groups".into())),
            bound_audiences: Some(Some(vec!["a1".into(), "a2".into()])),
            bound_subject: Some(Some("subject".into())),
            bound_claims: Some(json!({"department": "foo"})),
            claim_mappings: Some(json!({"foo": "bar"})),
            oidc_scopes: Some(Some(vec!["oidc".into(), "oauth".into()])),
            token_user_id: Some(Some("uid".into())),
            token_role_ids: Some(Some(vec!["r1".into(), "r2".into()])),
            token_project_id: Some(Some("pid".into())),
        };

        assert_eq!(
            update(&config, &db, "1", req).await.unwrap(),
            get_mapping_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "federated_mapping" SET "name" = $1, "idp_id" = $2, "allowed_redirect_uris" = $3, "user_claim" = $4, "user_claim_json_pointer" = $5, "groups_claim" = $6, "bound_audiences" = $7, "bound_subject" = $8, "bound_claims" = $9, "oidc_scopes" = $10, "claim_mappings" = $11, "token_user_id" = $12, "token_role_ids" = $13, "token_project_id" = $14 WHERE "federated_mapping"."id" = $15 RETURNING "id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id""#,
                    [
                        "name".into(),
                        "idp".into(),
                        "url".into(),
                        "sub".into(),
                        ".".into(),
                        "groups".into(),
                        "a1,a2".into(),
                        "subject".into(),
                        json!({"department": "foo"}).into(),
                        "oidc,oauth".into(),
                        json!({"foo": "bar"}).into(),
                        "uid".into(),
                        "r1,r2".into(),
                        "pid".into(),
                        "1".into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        delete(&config, &db, "id").await.unwrap();
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "federated_mapping" WHERE "federated_mapping"."id" = $1"#,
                ["id".into()]
            ),]
        );
    }
}
