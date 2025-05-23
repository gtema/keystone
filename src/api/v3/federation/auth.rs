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

use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::{StatusCode, header::LOCATION},
    response::IntoResponse,
};
use chrono::Local;
use std::collections::HashSet;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};

use crate::api::types::Scope as ApiScope;
use crate::api::v3::federation::error::OidcError;
use crate::api::v3::federation::types::*;
use crate::api::{
    common::{find_project_from_scope, get_domain},
    error::KeystoneApiError,
};
use crate::federation::FederationApi;
use crate::federation::types::{
    AuthState, MappingListParameters as ProviderMappingListParameters, Scope as ProviderScope,
};
use crate::keystone::ServiceState;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(post, get))
}

/// Authenticate using identity provider
#[utoipa::path(
    get,
    path = "/identity_providers/{idp_id}/auth",
    description = "Authenticate using identity provider",
    responses(
        (status = CREATED, description = "identity provider object", body = IdentityProviderAuthResponse),
    ),
    tag="identity_providers"
)]
#[tracing::instrument(name = "api::identity_provider_auth", level = "debug", skip(state))]
#[debug_handler]
pub async fn get(
    State(state): State<ServiceState>,
    Path(idp_id): Path<String>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    if let Some(discovery_url) = &idp.oidc_discovery_url {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
            &http_client,
        )
        .await
        .map_err(|err| OidcError::discovery(&err))?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(idp.oidc_client_id.expect("client_id is mandatory")),
            idp.oidc_client_secret.map(ClientSecret::new),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8080/v3/federation/auth/callback".to_string())
                .map_err(OidcError::from)?,
        );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        state
            .provider
            .get_federation_provider()
            .create_auth_state(
                &state.db,
                AuthState {
                    state: csrf_token.secret().clone(),
                    nonce: nonce.secret().clone(),
                    idp_id: idp.id.clone(),
                    mapping_id: String::from("kc"),
                    redirect_uri: String::new(),
                    pkce_verifier: pkce_verifier.into_secret(),
                    started_at: Local::now().into(),
                    scope: None,
                },
            )
            .await?;

        debug!(
            "url: {:?}, csrf: {:?}, nonce: {:?}",
            auth_url,
            csrf_token.secret(),
            nonce.secret()
        );
        return Ok((StatusCode::FOUND, [(LOCATION, &auth_url.to_string())]).into_response());
        //return Ok(Redirect::with_status_code(StatusCode::FOUND, &auth_url.to_string()).into_response());
    }

    Ok((StatusCode::CREATED).into_response())
}

/// Authenticate using identity provider
#[utoipa::path(
    post,
    path = "/identity_providers/{idp_id}/auth",
    description = "Authenticate using identity provider",
    responses(
        (status = CREATED, description = "identity provider object", body = IdentityProviderAuthResponse),
    ),
    tag="identity_providers"
)]
#[tracing::instrument(name = "api::identity_provider_auth", level = "debug", skip(state))]
#[debug_handler]
pub async fn post(
    State(state): State<ServiceState>,
    Path(idp_id): Path<String>,
    Json(req): Json<IdentityProviderAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    let mapping = if let Some(mapping_id) = req.mapping_id {
        state
            .provider
            .get_federation_provider()
            .get_mapping(&state.db, &mapping_id)
            .await
            .map(|x| {
                x.ok_or_else(|| KeystoneApiError::NotFound {
                    resource: "mapping".into(),
                    identifier: mapping_id.clone(),
                })
            })??
    } else if let Some(mapping_name) = req.mapping_name.or(idp.default_mapping_name) {
        state
            .provider
            .get_federation_provider()
            .list_mappings(
                &state.db,
                &ProviderMappingListParameters {
                    idp_id: Some(idp.id.clone()),
                    name: Some(mapping_name.clone()),
                    domain_id: None,
                },
            )
            .await?
            .first()
            .ok_or(KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: mapping_name.clone(),
            })?
            .to_owned()
    } else {
        return Err(OidcError::MappingRequired)?;
    };

    let client = if let Some(discovery_url) = &idp.oidc_discovery_url {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
            &http_client,
        )
        .await
        .map_err(|err| OidcError::discovery(&err))?;
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(idp.oidc_client_id.expect("client_id is mandatory")),
            idp.oidc_client_secret.map(ClientSecret::new),
        )
        // Set the URL the user will be redirected to after the authorization process.
        // TODO: Check the redirect uri against mapping.allowed_redirect_uris
        .set_redirect_uri(RedirectUrl::new(req.redirect_uri.clone()).map_err(OidcError::from)?)
    } else {
        return Err(OidcError::ClientWithoutDiscoveryNotSupported)?;
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut oidc_scopes: HashSet<Scope> = if let Some(mapping_scopes) = mapping.oidc_scopes {
        HashSet::from_iter(mapping_scopes.into_iter().map(Scope::new))
    } else {
        HashSet::new()
    };
    oidc_scopes.insert(Scope::new("openid".to_string()));

    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(oidc_scopes)
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    let scope: Option<ProviderScope> = match req.scope {
        Some(ApiScope::Project(scope)) => find_project_from_scope(&state, &scope)
            .await?
            .map(|x| ProviderScope::Project(x.id.clone())),
        Some(ApiScope::Domain(scope)) => get_domain(&state, scope.id.as_ref(), scope.name.as_ref())
            .await
            .map(|x| ProviderScope::Domain(x.id.clone()))
            .ok(),
        _ => None,
    };

    state
        .provider
        .get_federation_provider()
        .create_auth_state(
            &state.db,
            AuthState {
                state: csrf_token.secret().clone(),
                nonce: nonce.secret().clone(),
                idp_id: idp.id.clone(),
                mapping_id: mapping.id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                pkce_verifier: pkce_verifier.into_secret(),
                started_at: Local::now().into(),
                scope,
            },
        )
        .await?;

    debug!(
        "url: {:?}, csrf: {:?}, nonce: {:?}",
        auth_url,
        csrf_token.secret(),
        nonce.secret()
    );
    Ok(IdentityProviderAuthResponse {
        auth_url: auth_url.to_string(),
    }
    .into_response())
}
