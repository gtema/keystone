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
#[sea_orm(table_name = "access_rule")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub service: Option<String>,
    pub path: Option<String>,
    pub method: Option<String>,
    pub external_id: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::application_credential_access_rule::Entity")]
    ApplicationCredentialAccessRule,
}

impl Related<super::application_credential_access_rule::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApplicationCredentialAccessRule.def()
    }
}

impl Related<super::application_credential::Entity> for Entity {
    fn to() -> RelationDef {
        super::application_credential_access_rule::Relation::ApplicationCredential.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::application_credential_access_rule::Relation::AccessRule
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
