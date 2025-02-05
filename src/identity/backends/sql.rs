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

use async_trait::async_trait;
use chrono::{DateTime, Days};
use sea_orm::entity::*;
use sea_orm::query::LoaderTrait;
use sea_orm::query::*;
use sea_orm::DatabaseConnection;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::Config;
use crate::db::entity::federated_user;
use crate::db::entity::local_user;
use crate::db::entity::nonlocal_user;
use crate::db::entity::password;
use crate::db::entity::prelude::{
    FederatedUser, LocalUser, NonlocalUser, Password, User as DbUser, UserOption,
};
use crate::db::entity::user;
use crate::db::entity::user_option;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::IdentityProviderError;

use super::super::types::*;

#[derive(Debug)]
pub struct SqlDriver {
    pub config: Config,
}

impl SqlDriver {
    fn get_user_builder<O: IntoIterator<Item = user_option::Model>>(
        &self,
        user: &user::Model,
        opts: O,
    ) -> UserBuilder {
        let mut user_builder: UserBuilder = UserBuilder::default();
        user_builder.id(user.id.clone());
        user_builder.domain_id(user.domain_id.clone());
        // TODO: default enabled logic
        user_builder.enabled(user.enabled.unwrap_or(false));
        if let Some(extra) = &user.extra {
            user_builder.extra(serde_json::from_str::<Value>(extra).unwrap());
        }

        let mut user_opts: UserOptions = UserOptions::default();
        for opt in opts.into_iter() {
            match (opt.option_id.as_str(), opt.option_value) {
                ("1000", Some(val)) => {
                    user_opts.ignore_change_password_upon_first_use = val.parse().ok();
                }
                ("1001", Some(val)) => {
                    user_opts.ignore_password_expiry = val.parse().ok();
                }
                ("1002", Some(val)) => {
                    user_opts.ignore_lockout_failure_attempts = val.parse().ok();
                }
                ("1003", Some(val)) => {
                    user_opts.lock_password = val.parse().ok();
                }
                ("MFAR", Some(val)) => {
                    user_opts.multi_factor_auth_rules = serde_json::from_str(val.as_ref()).ok();
                }
                ("MFAE", Some(val)) => {
                    user_opts.multi_factor_auth_enabled = val.parse().ok();
                }
                _ => {}
            }
        }
        user_builder.options(user_opts);

        user_builder
    }

    fn get_local_user_builder<
        O: IntoIterator<Item = user_option::Model>,
        P: IntoIterator<Item = password::Model>,
    >(
        &self,
        user: &user::Model,
        data: local_user::Model,
        passwords: Option<P>,
        opts: O,
    ) -> UserBuilder {
        let mut user_builder: UserBuilder = self.get_user_builder(user, opts);
        user_builder.name(data.name.clone());
        if let Some(password_expires_days) = self.config.security_compliance.password_expires_days {
            if let Some(pass) = passwords {
                if let (Some(current_password), Some(options)) =
                    (pass.into_iter().next(), user_builder.get_options())
                {
                    if let Some(false) = options.ignore_password_expiry.or(Some(false)) {
                        if let Some(dt) =
                            DateTime::from_timestamp_micros(current_password.created_at_int)
                                .expect("invalid timestamp")
                                .checked_add_days(Days::new(password_expires_days))
                        {
                            user_builder.password_expires_at(dt);
                        }
                    }
                }
            }
        }

        user_builder
    }

    fn get_nonlocal_user_builder<O: IntoIterator<Item = user_option::Model>>(
        &self,
        user: &user::Model,
        data: nonlocal_user::Model,
        opts: O,
    ) -> UserBuilder {
        let mut user_builder: UserBuilder = self.get_user_builder(user, opts);
        user_builder.name(data.name.clone());
        user_builder
    }

    fn get_federated_user_builder<
        O: IntoIterator<Item = user_option::Model>,
        F: IntoIterator<Item = federated_user::Model>,
    >(
        &self,
        user: &user::Model,
        data: F,
        opts: O,
    ) -> UserBuilder {
        let mut user_builder: UserBuilder = self.get_user_builder(user, opts);
        if let Some(first) = data.into_iter().next() {
            if let Some(name) = first.display_name {
                user_builder.name(name.clone());
            }
        }
        user_builder
    }

    /// Fetch passwords for list of optional local user ids
    ///
    /// Returns vector of optional vectors with passwords in the same order as requested
    /// keeping None in place where local_user was empty.
    async fn load_local_users_passwords<L: IntoIterator<Item = Option<i32>>>(
        &self,
        db: &DatabaseConnection,
        user_ids: L,
    ) -> Result<
        //impl IntoIterator<Item = Option<impl IntoIterator<Item = password::Model>>>,
        Vec<Option<Vec<password::Model>>>,
        sea_orm::DbErr,
    > {
        let ids: Vec<Option<i32>> = user_ids.into_iter().collect();
        // Collect local user IDs that we need to query
        let keys: Vec<i32> = ids.iter().filter_map(Option::as_ref).copied().collect();

        // Fetch passwords for the local users by keys
        let passwords: Vec<password::Model> = Password::find()
            .filter(password::Column::LocalUserId.is_in(keys.clone()))
            .order_by(password::Column::CreatedAtInt, Order::Desc)
            .all(db)
            .await
            .unwrap();

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

    /// Load local user record with passwords from database
    async fn load_local_user_with_passwords<S: AsRef<str>>(
        &self,
        db: &DatabaseConnection,
        user_id: S,
    ) -> Result<
        Option<(local_user::Model, impl IntoIterator<Item = password::Model>)>,
        sea_orm::DbErr,
    > {
        let results: Vec<(local_user::Model, Vec<password::Model>)> = LocalUser::find()
            .filter(local_user::Column::UserId.eq(user_id.as_ref()))
            .find_with_related(Password)
            .all(db)
            .await
            .unwrap();
        Ok(results.first().cloned())
    }
}

#[async_trait]
impl IdentityBackend for SqlDriver {
    /// Fetch users from the database
    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn list(
        &self,
        db: &DatabaseConnection,
        params: &UserListParameters,
    ) -> Result<Vec<User>, IdentityProviderError> {
        tracing::debug!("Fetching user list!");
        // Prepare basic selects
        let mut user_select = DbUser::find();
        let mut local_user_select = LocalUser::find();
        let mut nonlocal_user_select = NonlocalUser::find();
        let mut federated_user_select = FederatedUser::find();

        if let Some(domain_id) = &params.domain_id {
            user_select = user_select.filter(user::Column::DomainId.eq(domain_id));
        }
        if let Some(name) = &params.name {
            local_user_select = local_user_select.filter(local_user::Column::Name.eq(name));
            nonlocal_user_select =
                nonlocal_user_select.filter(nonlocal_user::Column::Name.eq(name));
            federated_user_select =
                federated_user_select.filter(federated_user::Column::DisplayName.eq(name));
        }

        let db_users: Vec<user::Model> = user_select.all(db).await.unwrap();

        let user_opts: Vec<Vec<user_option::Model>> =
            db_users.load_many(UserOption, db).await.unwrap();

        let local_users: Vec<Option<local_user::Model>> =
            db_users.load_one(local_user_select, db).await.unwrap();

        let nonlocal_users: Vec<Option<nonlocal_user::Model>> =
            db_users.load_one(nonlocal_user_select, db).await.unwrap();

        let federated_users: Vec<Vec<federated_user::Model>> =
            db_users.load_many(federated_user_select, db).await.unwrap();

        let local_users_passwords: Vec<Option<Vec<password::Model>>> = self
            .load_local_users_passwords(db, local_users.iter().cloned().map(|u| u.map(|x| x.id)))
            .await
            .unwrap();

        let mut results: Vec<User> = Vec::new();
        for (u, (o, (l, (p, (n, f))))) in db_users.into_iter().zip(
            user_opts.into_iter().zip(
                local_users.into_iter().zip(
                    local_users_passwords
                        .into_iter()
                        .zip(nonlocal_users.into_iter().zip(federated_users.into_iter())),
                ),
            ),
        ) {
            if l.is_none() && n.is_none() && f.is_empty() {
                continue;
            }
            let user_builder: UserBuilder = if let Some(local) = l {
                self.get_local_user_builder(&u, local, p.map(|x| x.into_iter()), o)
            } else if let Some(nonlocal) = n {
                self.get_nonlocal_user_builder(&u, nonlocal, o)
            } else if !f.is_empty() {
                self.get_federated_user_builder(&u, f, o)
            } else {
                return Err(IdentityDatabaseError::MalformedUser(u.id))?;
            };
            results.push(user_builder.build()?);
        }

        //let select: Vec<(String, Option<String>, )>  = DbUser::find()
        //let select = DbUser::find();
        //let select  = Prefixer::new(DbUser::find().select_only())
        //    .add_columns(DbUser)
        //    .add_columns(LocalUser)
        //    .add_columns(NonlocalUser)
        //    .selector
        //    .left_join(LocalUser)
        //    .left_join(NonlocalUser)
        //    //.left_join(FederatedUser)
        //    .into_model::<DbUserData>()
        //    .all(db)
        //    .await
        //    .unwrap();
        Ok(results)
    }

    #[tracing::instrument(level = "debug", skip(self, db))]
    async fn get(
        &self,
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Option<User>, IdentityProviderError> {
        let user_select = DbUser::find_by_id(&user_id);

        let db_user: Option<user::Model> = user_select.one(db).await.unwrap();

        if let Some(user) = &db_user {
            let user_opts: Vec<user_option::Model> =
                user.find_related(UserOption).all(db).await.unwrap();

            let user_builder: UserBuilder = if let Some(local_user_with_passwords) = self
                .load_local_user_with_passwords(db, &user_id)
                .await
                .unwrap()
            {
                self.get_local_user_builder(
                    user,
                    local_user_with_passwords.0,
                    Some(local_user_with_passwords.1),
                    user_opts,
                )
            } else if let Some(nonlocal_user) =
                user.find_related(NonlocalUser).one(db).await.unwrap()
            {
                self.get_nonlocal_user_builder(user, nonlocal_user, user_opts)
            } else {
                let federated_user = user.find_related(FederatedUser).all(db).await.unwrap();
                if !federated_user.is_empty() {
                    self.get_federated_user_builder(user, federated_user, user_opts)
                } else {
                    return Err(IdentityDatabaseError::MalformedUser(user_id.clone()))?;
                }
            };

            return Ok(Some(user_builder.build()?));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::local_user;
    use crate::db::entity::password;
    use crate::db::entity::user;
    use crate::db::entity::user_option;

    use super::*;

    impl Default for user::Model {
        fn default() -> Self {
            Self {
                id: String::new(),
                extra: None,
                enabled: None,
                default_project_id: None,
                created_at: None,
                last_active_at: None,
                domain_id: String::new(),
            }
        }
    }

    impl Default for local_user::Model {
        fn default() -> Self {
            Self {
                id: 0,
                user_id: String::new(),
                domain_id: String::new(),
                name: String::new(),
                failed_auth_at: None,
                failed_auth_count: None,
            }
        }
    }

    fn get_user_mock(user_id: String) -> user::Model {
        user::Model {
            id: user_id.clone(),
            domain_id: "foo_domain".into(),
            enabled: Some(true),
            ..Default::default()
        }
    }

    fn get_local_user_with_password_mock(
        user_id: String,
        cnt_password: usize,
    ) -> Vec<(local_user::Model, password::Model)> {
        let lu = local_user::Model {
            user_id: user_id.clone(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            ..Default::default()
        };
        let mut passwords: Vec<password::Model> = Vec::new();
        for i in 0..cnt_password {
            passwords.push(password::Model {
                id: i as i32,
                local_user_id: 1,
                expires_at: None,
                self_service: false,
                password_hash: None,
                created_at_int: 12345,
                expires_at_int: None,
            });
        }
        passwords
            .into_iter()
            .map(|x| (lu.clone(), x.clone()))
            .collect()
    }

    #[tokio::test]
    async fn test_get_user_local() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_user_mock("1".into())],
            ])
            .append_query_results([
                //// Second query result - user options
                vec![user_option::Model {
                    user_id: "1".into(),
                    option_id: "1000".into(),
                    option_value: Some("true".into()),
                }],
            ])
            .append_query_results([
                // Third query result - local user with passwords
                get_local_user_with_password_mock("1".into(), 1),
            ])
            .into_connection();
        let driver = SqlDriver {
            config: Config::default(),
        };
        assert_eq!(
            driver.get(&db, "1".into()).await.unwrap().unwrap(),
            User {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "Apple Cake".to_owned(),
                enabled: true,
                extra: None,
                password_expires_at: None,
                options: UserOptions {
                    ignore_change_password_upon_first_use: Some(true),
                    ..Default::default()
                }
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."id", "user"."extra", "user"."enabled", "user"."default_project_id", "user"."created_at", "user"."last_active_at", "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" INNER JOIN "user" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" = $1"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."expires_at" AS "B_expires_at", "password"."self_service" AS "B_self_service", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC"#,
                    ["1".into()]
                ),
            ]
        );
    }
}
