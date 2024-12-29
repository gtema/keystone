//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use sea_orm::entity::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "entity_type")]
pub enum EntityType {
    #[sea_orm(string_value = "user")]
    User,
    #[sea_orm(string_value = "group")]
    Group,
}
#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "type")]
pub enum Type {
    #[sea_orm(string_value = "UserProject")]
    UserProject,
    #[sea_orm(string_value = "GroupProject")]
    GroupProject,
    #[sea_orm(string_value = "UserDomain")]
    UserDomain,
    #[sea_orm(string_value = "GroupDomain")]
    GroupDomain,
}
