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
//! Role assignment database backend.

//use crate::assignment::AssignmentProviderError;
use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::db::entity::{
    assignment as db_assignment, role as db_role, sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};

mod check;
mod create;
mod list;

pub use check::check;
pub use create::create;
pub use list::list;
pub use list::list_for_multiple_actors_and_targets;

impl TryFrom<db_assignment::Model> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: db_assignment::Model) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.role_id.clone());
        builder.actor_id(value.actor_id.clone());
        builder.target_id(value.target_id.clone());
        builder.inherited(value.inherited);
        builder.r#type(AssignmentType::try_from(value.r#type)?);

        Ok(builder.build()?)
    }
}

impl TryFrom<db_system_assignment::Model> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: db_system_assignment::Model) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.role_id.clone());
        builder.actor_id(value.actor_id.clone());
        builder.target_id(value.target_id.clone());
        builder.inherited(value.inherited);
        builder.r#type(AssignmentType::try_from(value.r#type.as_ref())?);

        Ok(builder.build()?)
    }
}

impl TryFrom<&db_assignment::Model> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: &db_assignment::Model) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.role_id.clone());
        builder.actor_id(value.actor_id.clone());
        builder.target_id(value.target_id.clone());
        builder.inherited(value.inherited);
        builder.r#type(AssignmentType::try_from(value.r#type.clone())?);

        Ok(builder.build()?)
    }
}

impl TryFrom<(&db_assignment::Model, Option<&String>)> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(value: (&db_assignment::Model, Option<&String>)) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.0.role_id.clone());
        builder.actor_id(value.0.actor_id.clone());
        builder.target_id(value.0.target_id.clone());
        builder.inherited(value.0.inherited);
        builder.r#type(AssignmentType::try_from(value.0.r#type.clone())?);
        if let Some(val) = value.1 {
            builder.role_name(val.clone());
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<(db_assignment::Model, Option<db_role::Model>)> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(
        value: (db_assignment::Model, Option<db_role::Model>),
    ) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.0.role_id.clone());
        builder.actor_id(value.0.actor_id.clone());
        builder.target_id(value.0.target_id.clone());
        builder.inherited(value.0.inherited);
        builder.r#type(AssignmentType::try_from(value.0.r#type)?);
        if let Some(val) = &value.1 {
            builder.role_name(val.name.clone());
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<(db_system_assignment::Model, Option<db_role::Model>)> for Assignment {
    type Error = AssignmentDatabaseError;

    fn try_from(
        value: (db_system_assignment::Model, Option<db_role::Model>),
    ) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role_id(value.0.role_id.clone());
        builder.actor_id(value.0.actor_id.clone());
        builder.target_id(value.0.target_id.clone());
        builder.inherited(value.0.inherited);
        builder.r#type(AssignmentType::try_from(value.0.r#type.as_ref())?);
        if let Some(val) = &value.1 {
            builder.role_name(val.name.clone());
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<DbAssignmentType> for AssignmentType {
    type Error = AssignmentDatabaseError;
    fn try_from(value: DbAssignmentType) -> Result<Self, Self::Error> {
        match value {
            DbAssignmentType::GroupDomain => Ok(Self::GroupDomain),
            DbAssignmentType::GroupProject => Ok(Self::GroupProject),
            DbAssignmentType::UserDomain => Ok(Self::UserDomain),
            DbAssignmentType::UserProject => Ok(Self::UserProject),
        }
    }
}

impl TryFrom<&AssignmentType> for DbAssignmentType {
    type Error = AssignmentDatabaseError;
    fn try_from(value: &AssignmentType) -> Result<Self, Self::Error> {
        match value {
            AssignmentType::GroupDomain => Ok(Self::GroupDomain),
            AssignmentType::GroupProject => Ok(Self::GroupProject),
            AssignmentType::UserDomain => Ok(Self::UserDomain),
            AssignmentType::UserProject => Ok(Self::UserProject),
            AssignmentType::UserSystem => {
                Err(Self::Error::InvalidAssignmentType("UserSystem".into()))
            }
            AssignmentType::GroupSystem => {
                Err(Self::Error::InvalidAssignmentType("GroupSystem".into()))
            }
        }
    }
}

impl TryFrom<&str> for AssignmentType {
    type Error = AssignmentDatabaseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "GroupDomain" => Ok(Self::GroupDomain),
            "GroupProject" => Ok(Self::GroupProject),
            "GroupSystem" => Ok(Self::GroupSystem),
            "UserDomain" => Ok(Self::UserDomain),
            "UserProject" => Ok(Self::UserProject),
            "UserSystem" => Ok(Self::UserSystem),
            _ => Err(AssignmentDatabaseError::InvalidAssignmentType(value.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::Value;
    use std::collections::BTreeMap;

    use crate::db::entity::{
        assignment, implied_role, role, sea_orm_active_enums, system_assignment,
    };

    pub(super) fn get_role_assignment_mock<S: AsRef<str>>(role_id: S) -> assignment::Model {
        assignment::Model {
            role_id: role_id.as_ref().to_string(),
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: sea_orm_active_enums::Type::UserProject,
            inherited: false,
        }
    }

    pub(super) fn get_role_system_assignment_mock<S: AsRef<str>>(
        role_id: S,
    ) -> system_assignment::Model {
        system_assignment::Model {
            role_id: role_id.as_ref().to_string(),
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: "UserSystem".into(),
            inherited: false,
        }
    }

    pub(super) fn get_role_mock<SI: AsRef<str>, SN: AsRef<str>>(
        role_id: SI,
        role_name: SN,
    ) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "id".to_string(),
                Value::String(Some(Box::new(role_id.as_ref().to_string()))),
            ),
            (
                "name".to_string(),
                Value::String(Some(Box::new(role_name.as_ref().to_string()))),
            ),
        ])
    }

    pub(super) fn get_implied_rules_mock() -> Vec<implied_role::Model> {
        vec![implied_role::Model {
            prior_role_id: "1".to_string(),
            implied_role_id: "2".to_string(),
        }]
    }

    pub(super) fn get_role_assignment_with_role_mock<S: AsRef<str>>(
        role_id: S,
    ) -> (assignment::Model, role::Model) {
        (
            assignment::Model {
                role_id: role_id.as_ref().to_string(),
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: sea_orm_active_enums::Type::UserProject,
                inherited: false,
            },
            role::Model {
                id: role_id.as_ref().to_string(),
                name: role_id.as_ref().to_string(),
                extra: None,
                domain_id: String::new(),
                description: None,
            },
        )
    }

    pub(super) fn get_role_system_assignment_with_role_mock<S: AsRef<str>>(
        role_id: S,
    ) -> (system_assignment::Model, role::Model) {
        (
            system_assignment::Model {
                role_id: role_id.as_ref().to_string(),
                actor_id: "actor".into(),
                target_id: "system".into(),
                r#type: "UserSystem".into(),
                inherited: false,
            },
            role::Model {
                id: role_id.as_ref().to_string(),
                name: role_id.as_ref().to_string(),
                extra: None,
                domain_id: String::new(),
                description: None,
            },
        )
    }
}
