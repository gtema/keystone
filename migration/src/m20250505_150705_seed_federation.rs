use openstack_keystone::db::entity::prelude::{
    FederatedAuthState, FederatedIdentityProvider, FederatedMapping,
};
use openstack_keystone::db::entity::{federated_identity_provider, federated_mapping};

use sea_orm::entity::*;
use sea_orm_migration::{prelude::*, schema::*};
use serde_json::json;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        let github = federated_identity_provider::ActiveModel {
            id: Set("github".to_owned()),
            name: Set("github".to_owned()),
            domain_id: NotSet,
            oidc_discovery_url: NotSet,
            oidc_client_id: Set(Some("Ov23lit3ZDfkXrCz4FEP".to_owned())),
            oidc_client_secret: Set(Some("a4a64b0d874f14f35560f5dddd0d06b98cf62bc9".to_owned())),
            oidc_response_mode: NotSet,
            oidc_response_types: Set(Some("code".to_owned())),
            jwt_validation_pubkeys: NotSet,
            bound_issuer: NotSet,
            provider_config: Set(Some(
                json!({"authorization_endpoint": "https://github.com/login/oauth/authorize"})
                    .into(),
            )),
        };
        let gh = FederatedIdentityProvider::insert(github)
            .exec(db)
            .await?
            .last_insert_id;

        let kc = federated_identity_provider::ActiveModel {
            id: Set("kc".to_owned()),
            name: Set("kc".to_owned()),
            domain_id: NotSet,
            oidc_discovery_url: Set(Some("http://localhost:8082/realms/master".to_owned())),
            oidc_client_id: Set(Some("keystone".to_owned())),
            oidc_client_secret: Set(Some("w7GMfkyFzLStHesMxMLgSlJexqa0gQ0F".to_owned())),
            oidc_response_mode: NotSet,
            oidc_response_types: Set(Some("code".to_owned())),
            jwt_validation_pubkeys: NotSet,
            bound_issuer: NotSet,
            provider_config: NotSet,
        };
        let kc1 = FederatedIdentityProvider::insert(kc)
            .exec(db)
            .await?
            .last_insert_id;

        let kcm = federated_mapping::ActiveModel {
            id: Set("kc".to_owned()),
            name: Set("kc".to_owned()),
            domain_id: NotSet,
            idp_id: Set(kc1),
            allowed_redirect_uris: Set(Some(
                "http://localhost:8080/v3/identity_providers/kc/callback".to_owned(),
            )),
            user_id_claim: Set("sub".to_owned()),
            user_name_claim: Set("preferred_username".to_owned()),
            domain_id_claim: Set(Some("domain_id".to_owned())),
            groups_claim: NotSet,
            bound_audiences: NotSet,
            bound_subject: NotSet,
            bound_claims: NotSet,
            oidc_scopes: NotSet,
            claim_mappings: NotSet,
            token_user_id: NotSet,
            token_role_ids: NotSet,
            token_project_id: NotSet,
        };
        let kcm1 = FederatedMapping::insert(kcm).exec(db).await?.last_insert_id;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        FederatedIdentityProvider::delete_many().exec(db).await?;
        FederatedMapping::delete_many().exec(db).await?;
        FederatedAuthState::delete_many().exec(db).await?;
        Ok(())
    }
}
