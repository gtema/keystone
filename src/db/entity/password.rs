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
#[sea_orm(table_name = "password")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub local_user_id: i32,
    pub self_service: bool,
    pub created_at: DateTime,
    pub expires_at: Option<DateTime>,
    pub password_hash: Option<String>,
    pub created_at_int: i64,
    pub expires_at_int: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::local_user::Entity",
        from = "Column::LocalUserId",
        to = "super::local_user::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    LocalUser,
}

impl Related<super::local_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LocalUser.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
