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

use chrono::Utc;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::config::Config;
use crate::db::entity::{
    federated_auth_state as db_federated_auth_state,
    prelude::FederatedAuthState as DbFederatedAuthState,
};
use crate::federation::backends::error::FederationDatabaseError;
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    state: I,
) -> Result<Option<AuthState>, FederationDatabaseError> {
    let select = DbFederatedAuthState::find_by_id(state.as_ref());

    let entry: Option<db_federated_auth_state::Model> = select.one(db).await?;
    entry.map(TryInto::try_into).transpose()
}

pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    rec: AuthState,
) -> Result<AuthState, FederationDatabaseError> {
    let scope: Option<serde_json::Value> = if let Some(scope) = rec.scope {
        Some(serde_json::to_value(&scope)?)
    } else {
        None
    };
    let entry = db_federated_auth_state::ActiveModel {
        state: Set(rec.state.clone()),
        idp_id: Set(rec.idp_id.clone()),
        mapping_id: Set(rec.mapping_id.clone()),
        nonce: Set(rec.nonce.clone()),
        redirect_uri: Set(rec.redirect_uri.clone()),
        pkce_verifier: Set(rec.pkce_verifier.clone()),
        expires_at: Set(rec.expires_at.naive_utc()),
        requested_scope: scope.map(Set).unwrap_or(NotSet).into(),
    };

    let db_entry: db_federated_auth_state::Model = entry.insert(db).await?;

    db_entry.try_into()
}

pub async fn delete<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
) -> Result<(), FederationDatabaseError> {
    let res = DbFederatedAuthState::delete_by_id(id.as_ref())
        .exec(db)
        .await?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(FederationDatabaseError::AuthStateNotFound(
            id.as_ref().to_string(),
        ))
    }
}

pub async fn delete_expired(
    _conf: &Config,
    db: &DatabaseConnection,
) -> Result<(), FederationDatabaseError> {
    DbFederatedAuthState::delete_many()
        .filter(db_federated_auth_state::Column::ExpiresAt.lt(Utc::now()))
        .exec(db)
        .await?;
    Ok(())
}

impl TryFrom<db_federated_auth_state::Model> for AuthState {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_auth_state::Model) -> Result<Self, Self::Error> {
        let mut builder = AuthStateBuilder::default();
        builder.state(value.state.clone());
        builder.nonce(value.nonce.clone());
        builder.idp_id(value.idp_id.clone());
        builder.mapping_id(value.mapping_id.clone());
        builder.redirect_uri(value.redirect_uri.clone());
        builder.pkce_verifier(value.pkce_verifier.clone());
        builder.expires_at(value.expires_at.and_utc());
        if let Some(scope) = value.requested_scope {
            builder.scope(serde_json::from_value::<Scope>(scope)?);
        }
        Ok(builder.build()?)
    }
}

//#[cfg(test)]
//mod tests {
//    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
//    use serde_json::json;
//
//    use crate::config::Config;
//    use crate::db::entity::federated_mapping;
//
//    use super::*;
//
//    fn get_mapping_mock<S: AsRef<str>>(id: S) -> federated_mapping::Model {
//        federated_mapping::Model {
//            id: id.as_ref().into(),
//            name: "name".into(),
//            domain_id: Some("did".into()),
//            idp_id: "idp".into(),
//            user_claim: "sub".into(),
//            ..Default::default()
//        }
//    }
//
//    #[tokio::test]
//    async fn test_get() {
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([vec![get_mapping_mock("1")]])
//            .into_connection();
//        let config = Config::default();
//        assert_eq!(
//            get(&config, &db, "1").await.unwrap().unwrap(),
//            Mapping {
//                id: "1".into(),
//                name: "name".into(),
//                domain_id: Some("did".into()),
//                idp_id: "idp".into(),
//                user_claim: "sub".into(),
//                ..Default::default()
//            }
//        );
//
//        assert_eq!(
//            db.into_transaction_log(),
//            [Transaction::from_sql_and_values(
//                DatabaseBackend::Postgres,
//                r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
//                ["1".into(), 1u64.into()]
//            ),]
//        );
//    }
//
//    #[tokio::test]
//    async fn test_list() {
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([vec![get_mapping_mock("1")]])
//            .append_query_results([vec![get_mapping_mock("1")]])
//            .into_connection();
//        let config = Config::default();
//        assert!(
//            list(&config, &db, &MappingListParameters::default())
//                .await
//                .is_ok()
//        );
//        assert_eq!(
//            list(
//                &config,
//                &db,
//                &MappingListParameters {
//                    name: Some("mapping_name".into()),
//                    domain_id: Some("did".into()),
//                    idp_id: Some("idp".into())
//                }
//            )
//            .await
//            .unwrap(),
//            vec![Mapping {
//                id: "1".into(),
//                name: "name".into(),
//                domain_id: Some("did".into()),
//                idp_id: "idp".into(),
//                user_claim: "sub".into(),
//                ..Default::default()
//            }]
//        );
//
//        assert_eq!(
//            db.into_transaction_log(),
//            [
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping""#,
//                    []
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."name" = $1 AND "federated_mapping"."domain_id" = $2 AND "federated_mapping"."idp_id" = $3"#,
//                    ["mapping_name".into(), "did".into(), "idp".into()]
//                ),
//            ]
//        );
//    }
//
//    #[tokio::test]
//    async fn test_create() {
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([vec![get_mapping_mock("1")]])
//            .into_connection();
//        let config = Config::default();
//
//        let req = Mapping {
//            id: "1".into(),
//            name: "mapping".into(),
//            domain_id: Some("foo_domain".into()),
//            idp_id: "idp".into(),
//            allowed_redirect_uris: Some(vec!["url".into()]),
//            user_claim: "sub".into(),
//            user_claim_json_pointer: Some(".".into()),
//            groups_claim: Some("groups".into()),
//            bound_audiences: Some(vec!["a1".into(), "a2".into()]),
//            bound_subject: Some("subject".into()),
//            bound_claims: Some(json!({"department": "foo"})),
//            claim_mappings: Some(json!({"foo": "bar"})),
//            oidc_scopes: Some(vec!["oidc".into(), "oauth".into()]),
//            token_user_id: Some("uid".into()),
//            token_role_ids: Some(vec!["r1".into(), "r2".into()]),
//            token_project_id: Some("pid".into()),
//        };
//
//        assert_eq!(
//            create(&config, &db, req).await.unwrap(),
//            get_mapping_mock("1").try_into().unwrap()
//        );
//        assert_eq!(
//            db.into_transaction_log(),
//            [Transaction::from_sql_and_values(
//                DatabaseBackend::Postgres,
//                r#"INSERT INTO "federated_mapping" ("id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING "id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id""#,
//                [
//                    "1".into(),
//                    "mapping".into(),
//                    "idp".into(),
//                    "foo_domain".into(),
//                    "url".into(),
//                    "sub".into(),
//                    ".".into(),
//                    "groups".into(),
//                    "a1,a2".into(),
//                    "subject".into(),
//                    json!({"department": "foo"}).into(),
//                    "oidc,oauth".into(),
//                    json!({"foo": "bar"}).into(),
//                    "uid".into(),
//                    "r1,r2".into(),
//                    "pid".into(),
//                ]
//            ),]
//        );
//    }
//
//    #[tokio::test]
//    async fn test_update() {
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([vec![get_mapping_mock("1")], vec![get_mapping_mock("1")]])
//            .append_exec_results([MockExecResult {
//                rows_affected: 1,
//                ..Default::default()
//            }])
//            .into_connection();
//        let config = Config::default();
//
//        let req = MappingUpdate {
//            name: Some("name".into()),
//            idp_id: Some("idp".into()),
//            allowed_redirect_uris: Some(Some(vec!["url".into()])),
//            user_claim: Some("sub".into()),
//            user_claim_json_pointer: Some(Some(".".into())),
//            groups_claim: Some(Some("groups".into())),
//            bound_audiences: Some(Some(vec!["a1".into(), "a2".into()])),
//            bound_subject: Some(Some("subject".into())),
//            bound_claims: Some(json!({"department": "foo"})),
//            claim_mappings: Some(json!({"foo": "bar"})),
//            oidc_scopes: Some(Some(vec!["oidc".into(), "oauth".into()])),
//            token_user_id: Some(Some("uid".into())),
//            token_role_ids: Some(Some(vec!["r1".into(), "r2".into()])),
//            token_project_id: Some(Some("pid".into())),
//        };
//
//        assert_eq!(
//            update(&config, &db, "1", req).await.unwrap(),
//            get_mapping_mock("1").try_into().unwrap()
//        );
//        assert_eq!(
//            db.into_transaction_log(),
//            [
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_claim", "federated_mapping"."user_claim_json_pointer", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."claim_mappings", "federated_mapping"."token_user_id", "federated_mapping"."token_role_ids", "federated_mapping"."token_project_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
//                    ["1".into(), 1u64.into()]
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"UPDATE "federated_mapping" SET "name" = $1, "idp_id" = $2, "allowed_redirect_uris" = $3, "user_claim" = $4, "user_claim_json_pointer" = $5, "groups_claim" = $6, "bound_audiences" = $7, "bound_subject" = $8, "bound_claims" = $9, "oidc_scopes" = $10, "claim_mappings" = $11, "token_user_id" = $12, "token_role_ids" = $13, "token_project_id" = $14 WHERE "federated_mapping"."id" = $15 RETURNING "id", "name", "idp_id", "domain_id", "allowed_redirect_uris", "user_claim", "user_claim_json_pointer", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "claim_mappings", "token_user_id", "token_role_ids", "token_project_id""#,
//                    [
//                        "name".into(),
//                        "idp".into(),
//                        "url".into(),
//                        "sub".into(),
//                        ".".into(),
//                        "groups".into(),
//                        "a1,a2".into(),
//                        "subject".into(),
//                        json!({"department": "foo"}).into(),
//                        "oidc,oauth".into(),
//                        json!({"foo": "bar"}).into(),
//                        "uid".into(),
//                        "r1,r2".into(),
//                        "pid".into(),
//                        "1".into()
//                    ]
//                ),
//            ]
//        );
//    }
//
//    #[tokio::test]
//    async fn test_delete() {
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_exec_results([MockExecResult {
//                rows_affected: 1,
//                ..Default::default()
//            }])
//            .into_connection();
//        let config = Config::default();
//
//        delete(&config, &db, "id").await.unwrap();
//        assert_eq!(
//            db.into_transaction_log(),
//            [Transaction::from_sql_and_values(
//                DatabaseBackend::Postgres,
//                r#"DELETE FROM "federated_mapping" WHERE "federated_mapping"."id" = $1"#,
//                ["id".into()]
//            ),]
//        );
//    }
//}
