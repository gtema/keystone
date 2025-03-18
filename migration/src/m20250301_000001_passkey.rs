use openstack_keystone::db::entity::prelude::User;
use openstack_keystone::db::entity::user;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebauthnCredential::Table)
                    .if_not_exists()
                    .col(pk_auto(WebauthnCredential::Id))
                    .col(string_len(WebauthnCredential::UserId, 64))
                    .col(string_len(WebauthnCredential::CredentialId, 1024))
                    .col(string(WebauthnCredential::Passkey))
                    .col(string_len(WebauthnCredential::Type, 25))
                    .col(string_len_null(WebauthnCredential::Aaguid, 36))
                    .col(date_time(WebauthnCredential::CreatedAt))
                    .col(date_time_null(WebauthnCredential::LastUsedAt))
                    .col(date_time_null(WebauthnCredential::LastUpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-passkey-credential")
                            .from(WebauthnCredential::Table, WebauthnCredential::UserId)
                            .to(User, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WebauthnState::Table)
                    .if_not_exists()
                    .col(string_len(WebauthnCredential::UserId, 64))
                    .col(string(WebauthnState::State))
                    .col(string_len(WebauthnState::Type, 10))
                    .col(date_time(WebauthnCredential::CreatedAt))
                    .primary_key(Index::create().col(WebauthnState::UserId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-passkey-state")
                            .from(WebauthnState::Table, WebauthnState::UserId)
                            .to(User, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebauthnCredential::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(WebauthnState::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WebauthnCredential {
    Table,
    Id,
    UserId,
    CredentialId,
    Passkey,
    Type,
    Aaguid,
    CreatedAt,
    LastUsedAt,
    LastUpdatedAt,
}

#[derive(DeriveIden)]
enum WebauthnState {
    Table,
    UserId,
    State,
    CreatedAt,
    Type
}
