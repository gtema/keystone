use openstack_keystone::db::entity::prelude::Project;
use openstack_keystone::db::entity::project;
use sea_orm_migration::{prelude::*, schema::*};

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
                    .col(string_len(FederatedMapping::UserClaim, 64))
                    .col(string_len_null(FederatedMapping::UserClaimJsonPointer, 128))
                    .col(string_len_null(FederatedMapping::GroupsClaim, 64))
                    .col(string_len_null(FederatedMapping::BoundAudiences, 1024))
                    .col(string_len_null(FederatedMapping::BoundSubject, 128))
                    .col(json_null(FederatedMapping::BoundClaims))
                    .col(string_len_null(FederatedMapping::OidcScopes, 128))
                    .col(json_null(FederatedMapping::ClaimMappings))
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
}

#[derive(DeriveIden)]
enum FederatedMapping {
    Table,
    Id,
    DomainId,
    Name,
    IdpId,
    AllowedRedirectUris,
    UserClaim,
    UserClaimJsonPointer,
    GroupsClaim,
    BoundAudiences,
    BoundSubject,
    BoundClaims,
    OidcScopes,
    ClaimMappings,
    TokenUserId,
    TokenRoleIds,
    TokenProjectId,
}
