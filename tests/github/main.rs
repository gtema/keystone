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

use reqwest::Client;
use reqwest::header::AUTHORIZATION;
use std::env;

mod keystone_utils;

use keystone_utils::*;

use openstack_keystone::api::v4::auth::token::types::TokenResponse;

#[tokio::test]
async fn test_login_jwt() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let jwt = env::var("GITHUB_JWT").expect("GITHUB_JWT is set");
    let client = Client::new();

    let token = auth().await;
    let user = ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, mapping) = setup_github_idp(&token, &user).await.unwrap();

    let auth_rsp: TokenResponse = client
        .post(format!(
            "{}/v4/federation/identity_providers/{}/jwt",
            keystone_url, idp.identity_provider.id
        ))
        .header(AUTHORIZATION, jwt)
        .header("openstack-mapping", mapping.mapping.name)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("Token: {:?}", auth_rsp);
}
