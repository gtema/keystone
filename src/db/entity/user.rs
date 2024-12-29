//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub extra: Option<String>,
    pub enabled: Option<i8>,
    pub default_project_id: Option<String>,
    pub created_at: Option<DateTime>,
    pub last_active_at: Option<Date>,
    pub domain_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::expiring_user_group_membership::Entity")]
    ExpiringUserGroupMembership,
    #[sea_orm(has_many = "super::federated_user::Entity")]
    FederatedUser,
    #[sea_orm(has_many = "super::local_user::Entity")]
    LocalUser,
    #[sea_orm(has_many = "super::nonlocal_user::Entity")]
    NonlocalUser,
    #[sea_orm(has_many = "super::user_group_membership::Entity")]
    UserGroupMembership,
    #[sea_orm(has_many = "super::user_option::Entity")]
    UserOption,
}

impl Related<super::expiring_user_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ExpiringUserGroupMembership.def()
    }
}

impl Related<super::federated_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FederatedUser.def()
    }
}

impl Related<super::local_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LocalUser.def()
    }
}

impl Related<super::nonlocal_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::NonlocalUser.def()
    }
}

impl Related<super::user_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserGroupMembership.def()
    }
}

impl Related<super::user_option::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserOption.def()
    }
}

impl Related<super::group::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_group_membership::Relation::Group.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::user_group_membership::Relation::User.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
