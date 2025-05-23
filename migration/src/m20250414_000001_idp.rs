use openstack_keystone::db::entity::prelude::Project;
use openstack_keystone::db::entity::{federated_user, project};
use sea_orm_migration::{prelude::*, schema::*};
use sea_query::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(FederatedIdentityProvider::Table)
                    .if_not_exists()
                    .col(string_len(FederatedIdentityProvider::Id, 64).primary_key())
                    .col(string_len(FederatedIdentityProvider::Name, 255))
                    .col(string_len_null(FederatedIdentityProvider::DomainId, 64))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcDiscoveryUrl,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcClientId,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcClientSecret,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcResponseMode,
                        64,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcResponseTypes,
                        255,
                    ))
                    .col(text_null(FederatedIdentityProvider::JwtValidationPubkeys))
                    .col(string_len_null(FederatedIdentityProvider::BoundIssuer, 255))
                    .col(json_null(FederatedIdentityProvider::ProviderConfig))
                    .col(string_len_null(
                        FederatedIdentityProvider::DefaultMappingName,
                        255,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-project")
                            .from(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::DomainId,
                            )
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .name("idx-idp-name-domain")
                            .col(FederatedIdentityProvider::DomainId)
                            .col(FederatedIdentityProvider::Name),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FederatedMapping::Table)
                    .if_not_exists()
                    .col(string_len(FederatedMapping::Id, 64).primary_key())
                    .col(string_len(FederatedMapping::Name, 255))
                    .col(string_len(FederatedMapping::IdpId, 64))
                    .col(string_len_null(FederatedMapping::DomainId, 64))
                    .col(string_len_null(FederatedMapping::AllowedRedirectUris, 1024))
                    .col(string_len(FederatedMapping::UserIdClaim, 64))
                    .col(string_len(FederatedMapping::UserNameClaim, 64))
                    .col(string_len_null(FederatedMapping::DomainIdClaim, 64))
                    //.col(string_len_null(FederatedMapping::UserClaimJsonPointer, 128))
                    .col(string_len_null(FederatedMapping::GroupsClaim, 64))
                    .col(string_len_null(FederatedMapping::BoundAudiences, 1024))
                    .col(string_len_null(FederatedMapping::BoundSubject, 128))
                    .col(json_null(FederatedMapping::BoundClaims))
                    .col(string_len_null(FederatedMapping::OidcScopes, 128))
                    //.col(json_null(FederatedMapping::ClaimMappings))
                    .col(string_len_null(FederatedMapping::TokenUserId, 64))
                    .col(string_len_null(FederatedMapping::TokenRoleIds, 128))
                    .col(string_len_null(FederatedMapping::TokenProjectId, 128))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-mapping-idp")
                            .from(FederatedMapping::Table, FederatedMapping::IdpId)
                            .to(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-mapping-project")
                            .from(FederatedMapping::Table, FederatedMapping::DomainId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-idp-mapping-domain")
                    .table(FederatedMapping::Table)
                    .col(FederatedMapping::DomainId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FederatedAuthState::Table)
                    .if_not_exists()
                    .col(string_len(FederatedAuthState::IdpId, 64))
                    .col(string_len(FederatedAuthState::MappingId, 64))
                    .col(string_len(FederatedAuthState::State, 64).primary_key())
                    .col(string_len(FederatedAuthState::Nonce, 64))
                    .col(string_len(FederatedAuthState::RedirectUri, 256))
                    .col(string_len(FederatedAuthState::PkceVerifier, 64))
                    .col(date_time(FederatedAuthState::StartedAt))
                    .col(json_null(FederatedAuthState::RequestedScope))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-auth-state-idp")
                            .from(FederatedAuthState::Table, FederatedAuthState::IdpId)
                            .to(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-auth-state-mapping")
                            .from(FederatedAuthState::Table, FederatedAuthState::MappingId)
                            .to(FederatedMapping::Table, FederatedMapping::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        //manager
        //    .alter_table(
        //        Table::alter()
        //            .table(FederatedUser::Table)
        //            .modify_column(ColumnDef::new(federated_user::Column::ProtocolId).null())
        //            //.drop_foreign_key(FederatedUser::FederatedUserIdpIdFkey)
        //            .to_owned(),
        //    )
        //    .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FederatedAuthState::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(FederatedMapping::Table).to_owned())
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(FederatedIdentityProvider::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum FederatedIdentityProvider {
    Table,
    Id,
    DomainId,
    Name,
    OidcDiscoveryUrl,
    OidcClientId,
    OidcClientSecret,
    OidcResponseMode,
    OidcResponseTypes,
    BoundIssuer,
    JwtValidationPubkeys,
    ProviderConfig,
    DefaultMappingName,
}

#[derive(DeriveIden)]
enum FederatedMapping {
    Table,
    Id,
    DomainId,
    Name,
    IdpId,
    AllowedRedirectUris,
    UserIdClaim,
    UserNameClaim,
    DomainIdClaim,
    GroupsClaim,
    BoundAudiences,
    BoundSubject,
    BoundClaims,
    OidcScopes,
    TokenUserId,
    TokenRoleIds,
    TokenProjectId,
}

#[derive(DeriveIden)]
enum FederatedAuthState {
    Table,
    IdpId,
    MappingId,
    State,
    Nonce,
    RedirectUri,
    PkceVerifier,
    StartedAt,
    RequestedScope,
}

#[derive(DeriveIden)]
enum FederatedUser {
    Table,
    ProtocolId,
    FederatedUserIdpIdFkey,
}
