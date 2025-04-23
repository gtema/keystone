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
                            .name("fk-user-passkey-credential")
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
    //JwksUrl,
    //JwksCaPem,
    ProviderConfig,
}
