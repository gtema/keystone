// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "implied_role")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub prior_role_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub implied_role_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::role::Entity",
        from = "Column::ImpliedRoleId",
        to = "super::role::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Role2,
    #[sea_orm(
        belongs_to = "super::role::Entity",
        from = "Column::PriorRoleId",
        to = "super::role::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Role1,
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::ImpliedRoleId",
        to = "Column::PriorRoleId"
    )]
    SelfReferencing,
}

impl ActiveModelBehavior for ActiveModel {}

pub struct SelfReferencingLink;

impl Linked for SelfReferencingLink {
    type FromEntity = Entity;

    type ToEntity = Entity;

    fn link(&self) -> Vec<RelationDef> {
        vec![Relation::SelfReferencing.def()]
    }
}
