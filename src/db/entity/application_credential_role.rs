//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "application_credential_role")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub application_credential_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub role_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::application_credential::Entity",
        from = "Column::ApplicationCredentialId",
        to = "super::application_credential::Column::InternalId",
        on_update = "Restrict",
        on_delete = "Cascade"
    )]
    ApplicationCredential,
}

impl Related<super::application_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApplicationCredential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
