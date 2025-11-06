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
//! Common functionality used in the functional tests.

use eyre::Report;
use reqwest::Client;

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;

/// Get the password auth identity struct
pub fn get_password_auth<U, P, DID>(
    username: U,
    password: P,
    domain_id: DID,
) -> Result<PasswordAuth, Report>
where
    U: AsRef<str>,
    P: AsRef<str>,
    DID: AsRef<str>,
{
    PasswordAuthBuilder::default()
        .user(
            UserPasswordBuilder::default()
                .name(username.as_ref())
                .password(password.as_ref())
                .domain(DomainBuilder::default().id(domain_id.as_ref()).build()?)
                .build()?,
        )
        .build()
        .map_err(Into::into)
}

/// Authenticate using the passed password auth and the scope.
pub async fn auth<U>(
    keystone_url: U,
    password_auth: PasswordAuth,
    scope: Option<Scope>,
) -> Result<String, Report>
where
    U: AsRef<str> + std::fmt::Display,
{
    let identity = IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(password_auth)
        .build()?;
    let auth_request = AuthRequest {
        auth: AuthRequestInner { identity, scope },
    };
    let client = Client::new();
    Ok(client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&serde_json::to_value(auth_request)?)
        .send()
        .await
        .unwrap()
        .headers()
        .get("X-Subject-Token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string())
}
