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
#[sea_orm(table_name = "request_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub request_secret: String,
    pub verifier: Option<String>,
    pub authorizing_user_id: Option<String>,
    pub requested_project_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub role_ids: Option<String>,
    pub consumer_id: String,
    pub expires_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::consumer::Entity",
        from = "Column::ConsumerId",
        to = "super::consumer::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Consumer,
}

impl Related<super::consumer::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Consumer.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
