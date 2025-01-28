use sea_orm::entity::prelude::*;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    pub domain_id: String,
}

/// Cake relation
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Local User relation
    #[sea_orm(has_one = "super::local_user::Entity")]
    LocalUser,
}

//impl RelationTrait for Relation {
//    fn def(&self) -> RelationDef {
//        match self {
//            Self::LocalUser => Entity::has_one(super::local_user::Entity).into(),
//        }
//    }
//}

impl Related<super::local_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LocalUser.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
