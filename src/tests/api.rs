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

use sea_orm::DatabaseConnection;
use std::sync::Arc;

use crate::assignment::MockAssignmentProvider;
use crate::config::Config;
use crate::identity::MockIdentityProvider;
use crate::keystone::{Service, ServiceState};
use crate::provider::ProviderBuilder;
use crate::resource::MockResourceProvider;
use crate::token::{MockTokenProvider, Token, TokenProviderError, UnscopedToken};

pub(crate) fn get_mocked_state_unauthed() -> ServiceState {
    let db = DatabaseConnection::Disconnected;
    let config = Config::default();
    let assignment_mock = MockAssignmentProvider::default();
    let identity_mock = MockIdentityProvider::default();
    let resource_mock = MockResourceProvider::default();
    let mut token_mock = MockTokenProvider::default();
    token_mock
        .expect_validate_token()
        .returning(|_, _| Err(TokenProviderError::InvalidToken));

    let provider = ProviderBuilder::default()
        .config(config.clone())
        .assignment(assignment_mock)
        .identity(identity_mock)
        .resource(resource_mock)
        .token(token_mock)
        .build()
        .unwrap();

    Arc::new(Service::new(config, db, provider).unwrap())
}

pub(crate) fn get_mocked_state(identity_mock: MockIdentityProvider) -> ServiceState {
    let db = DatabaseConnection::Disconnected;
    let config = Config::default();
    let mut token_mock = MockTokenProvider::default();
    let resource_mock = MockResourceProvider::default();
    token_mock.expect_validate_token().returning(|_, _| {
        Ok(Token::Unscoped(UnscopedToken {
            user_id: "bar".into(),
            ..Default::default()
        }))
    });
    let assignment_mock = MockAssignmentProvider::default();

    let provider = ProviderBuilder::default()
        .config(config.clone())
        .assignment(assignment_mock)
        .identity(identity_mock)
        .resource(resource_mock)
        .token(token_mock)
        .build()
        .unwrap();

    Arc::new(Service::new(config, db, provider).unwrap())
}
