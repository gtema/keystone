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

use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::DatabaseConnection;
use std::collections::HashMap;

use crate::config::Config;
use crate::db::entity::{
    local_user, password,
    prelude::{LocalUser, Password},
};
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::UserCreate;

/// Load local user record with passwords from database
pub async fn load_local_user_with_passwords<S: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: S,
) -> Result<
    Option<(local_user::Model, impl IntoIterator<Item = password::Model>)>,
    IdentityDatabaseError,
> {
    let results: Vec<(local_user::Model, Vec<password::Model>)> = LocalUser::find()
        .filter(local_user::Column::UserId.eq(user_id.as_ref()))
        .find_with_related(Password)
        .all(db)
        .await?;
    Ok(results.first().cloned())
}

/// Fetch passwords for list of optional local user ids
///
/// Returns vector of optional vectors with passwords in the same order as requested
/// keeping None in place where local_user was empty.
pub async fn load_local_users_passwords<L: IntoIterator<Item = Option<i32>>>(
    db: &DatabaseConnection,
    user_ids: L,
) -> Result<
    //impl IntoIterator<Item = Option<impl IntoIterator<Item = password::Model>>>,
    Vec<Option<Vec<password::Model>>>,
    IdentityDatabaseError,
> {
    let ids: Vec<Option<i32>> = user_ids.into_iter().collect();
    // Collect local user IDs that we need to query
    let keys: Vec<i32> = ids.iter().filter_map(Option::as_ref).copied().collect();

    // Fetch passwords for the local users by keys
    let passwords: Vec<password::Model> = Password::find()
        .filter(password::Column::LocalUserId.is_in(keys.clone()))
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .all(db)
        .await?;

    // Prepare hashmap of passwords per local_user_id from requested users
    let mut hashmap: HashMap<i32, Vec<password::Model>> =
        keys.iter().fold(HashMap::new(), |mut acc, key| {
            acc.insert(*key, Vec::new());
            acc
        });

    // Collect passwords into hashmap by the local_user_id
    passwords.into_iter().for_each(|item| {
        let vec = hashmap
            .get_mut(&item.local_user_id)
            .expect("Failed finding key on passwords hashmap");
        vec.push(item);
    });

    // Prepare final result keeping the order of the requested local_users
    // with vec of passwords for the ones
    let result: Vec<Option<Vec<password::Model>>> = ids
        .iter()
        .map(|lid| lid.map(|x| hashmap.get(&x).cloned()).unwrap_or_default())
        .collect();

    Ok(result)
}

pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: &UserCreate,
) -> Result<local_user::Model, IdentityDatabaseError> {
    let mut entry = local_user::ActiveModel {
        id: NotSet,
        user_id: Set(user.id.clone()),
        domain_id: Set(user.domain_id.clone()),
        name: Set(user.name.clone()),
        failed_auth_count: NotSet,
        failed_auth_at: NotSet,
    };
    // Set failed_auth_count to 0 if compliance disabling is on
    if let Some(true) = &user.enabled {
        if conf
            .security_compliance
            .disable_user_account_days_inactive
            .is_some()
        {
            entry.failed_auth_count = Set(Some(0));
        }
    }

    let db_user: local_user::Model = entry.insert(db).await?;

    Ok(db_user)
}
