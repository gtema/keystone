//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use super::sea_orm_active_enums::EntityType;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "id_mapping")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub public_id: String,
    pub domain_id: String,
    pub local_id: String,
    pub entity_type: EntityType,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
