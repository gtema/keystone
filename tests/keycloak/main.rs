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

use bytes::Bytes;
use eyre::Report;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thirtyfour::prelude::*;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use openstack_keystone::api::v3::auth::token::types::TokenResponse;
use openstack_keystone::api::v3::federation::types::*;

async fn auth() -> String {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&json!({"auth": {"identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "name": "admin",
                    "password": "password",
                    "domain": {
                        "id": "default"
                    },
                }
            }
        },
        "scope": {
            "project": {
                "name": "admin",
                "domain": {"id": "default"}
            }
        }}}))
        .send()
        .await
        .unwrap()
        .headers()
        .get("X-Subject-Token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn setup_kecloak_idp<S: AsRef<str>>(
    token: S,
) -> Result<(IdentityProviderResponse, MappingResponse), Report> {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let keycloak_url = env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL is set");
    let client = Client::new();

    let idp: IdentityProviderResponse = client
        .post(format!("{}/v3/federation/identity_providers", keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "identity_provider": {
                "id": "kc",
                "name": "keycloak",
                "oidc_discovery_url": format!("{}/realms/master", keycloak_url),
                "oidc_client_id": "keystone",
                "oidc_client_secret": "keystone-secret",
             }
        }))
        .send()
        .await?
        .json()
        .await?;

    let mapping: MappingResponse = client
        .post(format!(
            "{}/v3/federation/mappings",
            keystone_url,
        ))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "mapping": {
                "id": "kc",
                "name": "keycloak",
                "idp_id": idp.identity_provider.id.clone(),
                "allowed_redirect_uris": ["http://localhost:8080/v3/identity_providers/kc/callback"],
                "user_id_claim": "sub",
                "user_name_claim": "preferred_username",
                "domain_id_claim": "domain_id"
             }
        }))
        .send()
        .await?.json().await?;

    Ok((idp, mapping))
}

/// Information for finishing the authorization request (received as a callback from `/authorize`
/// call)
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationAuthCodeCallbackResponse {
    /// Authorization code
    pub code: Option<String>,
    /// Authorization state
    pub state: Option<String>,
    /// IDP error
    pub error: Option<String>,
    /// IDP error description
    pub error_description: Option<String>,
}

/// Start the OAUTH2 callback server
async fn auth_callback_server(
    addr: SocketAddr,
    state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>>,
    cancel_token: CancellationToken,
) -> Result<(), Report> {
    let listener = TcpListener::bind(addr).await?;
    // Wait maximum 2 minute for auth processing
    let webserver_timeout = Duration::from_secs(120);
    loop {
        let state_clone = state.clone();

        tokio::select! {
            Ok((stream, _addr)) = listener.accept() => {
                let io = TokioIo::new(stream);
                let cancel_token_srv = cancel_token.clone();
                let cancel_token_conn = cancel_token.clone();

                let service = service_fn(move |req| {
                    let state_clone = state_clone.clone();
                    let cancel_token = cancel_token_srv.clone();
                    handle_request(req, state_clone, cancel_token)
                });

                tokio::task::spawn(async move {
                    let cancel_token = cancel_token_conn.clone();
                    if http1::Builder::new().serve_connection(io, service).await.is_err() {
                        cancel_token.cancel();
                    }
                });
            },
            _ = cancel_token.cancelled() => {
                break;
            },
            _ = tokio::time::sleep(webserver_timeout) => {
                cancel_token.cancel();
            }
        }
    }
    Ok(())
}

/// Server request handler function
async fn handle_request(
    req: Request<IncomingBody>,
    state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>>,
    cancel_token: CancellationToken,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Report> {
    println!("Got request {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/oidc/callback") => {
            if let Some(query) = req.uri().query() {
                let res = serde_urlencoded::from_bytes::<FederationAuthCodeCallbackResponse>(
                    query.as_bytes(),
                )?;

                if res.error_description.is_some() {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Empty::<Bytes>::new().boxed())
                        .unwrap());
                }
                let mut data = state.lock().expect("state lock can not be obtained");
                *data = Some(res);
                cancel_token.cancel();

                Ok(Response::builder()
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap())
            }
        }
        (&Method::POST, "/oidc/callback") => {
            let b = req.collect().await?.to_bytes();
            let res = serde_urlencoded::from_bytes::<FederationAuthCodeCallbackResponse>(&b)?;
            if res.error_description.is_some() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Empty::<Bytes>::new().boxed())
                    .unwrap());
            }
            let mut data = state.lock().expect("state lock can not be obtained");
            *data = Some(res);
            cancel_token.cancel();

            Ok(Response::builder()
                .body(Empty::<Bytes>::new().boxed())
                .unwrap())
        }
        _ => {
            // Return 404 not found response.
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::<Bytes>::new().boxed())
                .unwrap())
        }
    }
}

#[tokio::test]
async fn test_login_keycloak() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let token = auth().await;
    let (idp, mapping) = setup_kecloak_idp(&token).await.unwrap();

    let auth_req: IdentityProviderAuthResponse = client
        .post(format!(
            "{}/v3/federation/identity_providers/{}/auth",
            keystone_url, idp.identity_provider.id
        ))
        .json(&json!({
            "redirect_uri": "http://localhost:8050/oidc/callback",
            "mapping_id": mapping.mapping.id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Prepare the callback server
    let cancel_token = CancellationToken::new();
    let state: Arc<Mutex<Option<FederationAuthCodeCallbackResponse>>> = Arc::new(Mutex::new(None));

    tokio::spawn({
        let cancel_token = cancel_token.clone();
        async move {
            if let Ok(()) = signal::ctrl_c().await {
                cancel_token.cancel();
            }
        }
    });

    let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8050));
    let callback_handle = tokio::spawn({
        let cancel_token = cancel_token.clone();
        let state = state.clone();
        async move { auth_callback_server(socket_addr, state, cancel_token).await }
    });

    // Start the selenium part
    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless().unwrap();
    let driver = WebDriver::new(
        format!(
            "http://localhost:{}",
            env::var("BROWSERDRIVER_PORT").unwrap_or("4444".to_string())
        ),
        caps,
    )
    .await
    .unwrap();

    //let delay = Duration::new(5, 0);
    //driver.set_implicit_wait_timeout(delay).await.unwrap();

    println!("Going to {:?}", auth_req.auth_url.clone());
    driver.goto(auth_req.auth_url).await.unwrap();

    println!("Page source is {:?}", driver.source().await.unwrap());

    let username_input = driver.query(By::Id("username")).first().await.unwrap();
    username_input
        .send_keys(env::var("USER_NAME").expect("USER_NAME is set"))
        .await
        .unwrap();
    let password_input = driver.query(By::Id("password")).first().await.unwrap();
    password_input
        .send_keys(env::var("USER_PASSWORD").expect("USER_PASSWORD is set"))
        .await
        .unwrap();
    let login = driver.find(By::Id("kc-login")).await.unwrap();
    login.click().await.unwrap();

    driver.quit().await.unwrap();

    let _res = callback_handle.await.unwrap();

    let guard = state.lock().expect("poisoned guard");
    let res: FederationAuthCodeCallbackResponse = guard.clone().unwrap();

    let _auth_rsp: TokenResponse = client
        .post(format!("{}/v3/federation/oidc/callback", keystone_url))
        .json(&json!({
            "state": res.state,
            "code": res.code
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // TODO: Add checks for the response
}
