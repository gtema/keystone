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

use chrono::{DateTime, Days, Utc};
use serde_json::Value;
use tracing::error;

use crate::config::Config;
use crate::db::entity::federated_user;
use crate::db::entity::local_user;
use crate::db::entity::nonlocal_user;
use crate::db::entity::password;
use crate::db::entity::user;
use crate::db::entity::user_option;

use crate::identity::types::*;

pub fn get_user_builder<O: IntoIterator<Item = user_option::Model>>(
    user: &user::Model,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = UserResponseBuilder::default();
    user_builder.id(user.id.clone());
    user_builder.domain_id(user.domain_id.clone());
    // TODO: default enabled logic
    user_builder.enabled(user.enabled.unwrap_or(false));
    if let Some(extra) = &user.extra {
        user_builder.extra(
            serde_json::from_str::<Value>(extra)
                .inspect_err(|e| error!("failed to deserialize user extra: {e}"))
                .unwrap_or_default(),
        );
    }

    user_builder.options(UserOptions::from_iter(opts));

    user_builder
}

pub fn get_local_user_builder<
    O: IntoIterator<Item = user_option::Model>,
    P: IntoIterator<Item = password::Model>,
>(
    conf: &Config,
    user: &user::Model,
    data: local_user::Model,
    passwords: Option<P>,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = get_user_builder(user, opts);
    user_builder.name(data.name.clone());
    if let Some(password_expires_days) = conf.security_compliance.password_expires_days
        && let Some(pass) = passwords
        && let (Some(current_password), Some(options)) =
            (pass.into_iter().next(), user_builder.get_options())
        && let Some(false) = options.ignore_password_expiry.or(Some(false))
        && let Some(dt) = DateTime::from_timestamp_micros(current_password.created_at_int)
            .unwrap_or(DateTime::from_naive_utc_and_offset(
                current_password.created_at,
                Utc,
            ))
            .checked_add_days(Days::new(password_expires_days))
    {
        user_builder.password_expires_at(dt);
    }
    user_builder
}

pub fn get_nonlocal_user_builder<O: IntoIterator<Item = user_option::Model>>(
    user: &user::Model,
    data: nonlocal_user::Model,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = get_user_builder(user, opts);
    user_builder.name(data.name.clone());
    user_builder
}

pub fn get_federated_user_builder<
    O: IntoIterator<Item = user_option::Model>,
    F: IntoIterator<Item = federated_user::Model>,
>(
    user: &user::Model,
    data: F,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = get_user_builder(user, opts);
    let mut feds: Vec<Federation> = Vec::new();
    if let Some(first) = data.into_iter().next() {
        if let Some(name) = first.display_name {
            user_builder.name(name.clone());
        }

        let mut fed = FederationBuilder::default();
        fed.idp_id(first.idp_id.clone());
        fed.unique_id(first.unique_id.clone());
        let protocol = FederationProtocol {
            protocol_id: first.protocol_id.clone(),
            unique_id: first.unique_id.clone(),
        };
        fed.protocols(vec![protocol]);
        if let Ok(fed_obj) = fed.build() {
            feds.push(fed_obj);
        }
    }
    user_builder.federated(feds);
    user_builder
}
