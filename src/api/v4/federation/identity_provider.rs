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

//! Identity providers API
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

pub(crate) static DESCRIPTION: &str = r#"Identity providers API.

Identity provider resource allows to federate users from an external Identity Provider (i.e.
Keycloak, Azure AD, etc.).

Using the Identity provider requires creation of the mapping, which describes how to map attributes
of the remote Idp to local users.

Identity provider with an empty domain_id are considered globals and every domain may use it with
appropriate mapping.
"#;

mod create;
mod delete;
mod list;
mod show;
mod update;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, update::update, delete::remove))
}

#[cfg(test)]
mod tests {

    // for `collect`
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    // for `call`, `oneshot`, and `ready`

    use crate::config::Config;
    use crate::federation::MockFederationProvider;
    use crate::identity::types::UserResponse;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyError, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub(crate) fn get_mocked_state(
        federation_mock: MockFederationProvider,
        policy_allowed: bool,
        policy_allowed_see_other_domains: Option<bool>,
    ) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    user: Some(UserResponse {
                        id: "bar".into(),
                        domain_id: "udid".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .federation(federation_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        if policy_allowed {
            policy_factory_mock.expect_instantiate().returning(move || {
                let mut policy_mock = MockPolicy::default();
                if policy_allowed_see_other_domains.is_some_and(|x| x) {
                    policy_mock
                        .expect_enforce()
                        .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed_admin()));
                } else {
                    policy_mock
                        .expect_enforce()
                        .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
                }
                Ok(policy_mock)
            });
        } else {
            policy_factory_mock.expect_instantiate().returning(|| {
                let mut policy_mock = MockPolicy::default();
                policy_mock.expect_enforce().returning(|_, _, _, _| {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                });
                Ok(policy_mock)
            });
        }
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                policy_factory_mock,
            )
            .unwrap(),
        )
    }
}
