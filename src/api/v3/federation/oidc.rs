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

use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use eyre::WrapErr;
use serde_json::Value;
use tracing::debug;
use url::Url;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use openidconnect::core::{CoreGenderClaim, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IdTokenClaims, IssuerUrl, Nonce, PkceCodeVerifier,
    RedirectUrl, TokenResponse,
};

use crate::api::v3::auth::token::types::{
    Token as ApiResponseToken, TokenResponse as KeystoneTokenResponse,
};
use crate::api::v3::federation::error::OidcError;
use crate::api::v3::federation::types::*;
use crate::api::{Catalog, error::KeystoneApiError};
use crate::catalog::CatalogApi;
use crate::federation::FederationApi;
use crate::federation::types::Scope as ProviderScope;
use crate::federation::types::{
    identity_provider::IdentityProvider as ProviderIdentityProvider,
    mapping::Mapping as ProviderMapping,
};
use crate::identity::IdentityApi;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{FederationBuilder, FederationProtocol, UserCreateBuilder};
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;
use crate::token::TokenApi;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(callback))
}

/// Authenticate callback
#[utoipa::path(
    post,
    path = "/oidc/callback",
    description = "OIDC authentication callback",
    responses(
        (status = OK, description = "Authentication Token object", body = KeystoneTokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        ),
    ),
    ),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_auth_callback",
    level = "debug",
    skip(state)
)]
#[debug_handler]
pub async fn callback(
    State(state): State<ServiceState>,
    Json(query): Json<AuthCallbackParameters>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let auth_state = state
        .provider
        .get_federation_provider()
        .get_auth_state(&state.db, &query.state)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "auth state".into(),
            identifier: query.state.clone(),
        })?;

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state.db, &auth_state.idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: auth_state.idp_id.clone(),
            })
        })??;

    let mapping = state
        .provider
        .get_federation_provider()
        .get_mapping(&state.db, &auth_state.mapping_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: auth_state.mapping_id.clone(),
            })
        })??;

    debug!("Got code {:?}, state: {:?}", query.code, auth_state);
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let client = if let Some(discovery_url) = &idp.oidc_discovery_url {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
            &http_client,
        )
        .await
        .map_err(|err| OidcError::discovery(&err))?;
        OidcClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(idp.oidc_client_id.clone().expect("client_id is mandatory")),
            idp.oidc_client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(RedirectUrl::new(auth_state.redirect_uri).map_err(OidcError::from)?)
    } else {
        return Err(OidcError::ClientWithoutDiscoveryNotSupported)?;
    };

    // Set the URL the user will be redirected to after the authorization process.

    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code))
        .expect("valid code")
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| OidcError::request_token(&err))?;

    debug!("Response is {:?}", token_response);

    //// Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response.id_token().ok_or(OidcError::NoToken)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(auth_state.nonce))
        .map_err(OidcError::from)?;
    debug!("id_token: {:?}, claims: {:?}", id_token, claims,);
    if let Some(bound_issuer) = &idp.bound_issuer {
        if Url::parse(bound_issuer)
            .map_err(OidcError::from)
            .wrap_err_with(|| {
                format!(
                    "while parsing the mapping bound_issuer url: {}",
                    bound_issuer
                )
            })?
            == *claims.issuer().url()
        {}
    }

    let claims_as_json = serde_json::to_value(claims)?;
    debug!("Json: {:?}", claims_as_json);

    validate_bound_claims(&mapping, claims, &claims_as_json)?;
    let mapped_user_data = map_user_data(&idp, &mapping, &claims_as_json)?;

    let user = if let Some(existing_user) = state
        .provider
        .get_identity_provider()
        .find_federated_user(&state.db, &idp.id, &mapped_user_data.unique_id)
        .await?
    {
        // The user exists already
        existing_user

        // TODO: update user?
    } else {
        // New user
        let mut federated_user: FederationBuilder = FederationBuilder::default();
        federated_user.idp_id(idp.id);
        federated_user.unique_id(mapped_user_data.unique_id.clone());
        federated_user.protocols(vec![FederationProtocol {
            protocol_id: "oidc".into(),
            unique_id: mapped_user_data.unique_id.clone(),
        }]);
        let mut user_builder: UserCreateBuilder = UserCreateBuilder::default();
        user_builder.id(String::new());
        user_builder.domain_id(mapped_user_data.domain_id);
        user_builder.enabled(true);
        user_builder.name(mapped_user_data.user_name);
        user_builder.federated(Vec::from([federated_user
            .build()
            .map_err(IdentityProviderError::from)?]));

        state
            .provider
            .get_identity_provider()
            .create_user(
                &state.db,
                user_builder.build().map_err(IdentityProviderError::from)?,
            )
            .await?
    };
    // TODO: Persist group memberships

    let (project, domain) = match &auth_state.scope {
        Some(ProviderScope::Project(pid)) => (
            Some(
                state
                    .provider
                    .get_resource_provider()
                    .get_project(&state.db, pid.as_ref())
                    .await?
                    .ok_or_else(|| KeystoneApiError::NotFound {
                        resource: "project".into(),
                        identifier: pid.clone(),
                    })?,
            ),
            None,
        ),
        Some(ProviderScope::Domain(did)) => (
            None,
            Some(
                state
                    .provider
                    .get_resource_provider()
                    .get_domain(&state.db, did.as_ref())
                    .await?
                    .ok_or_else(|| KeystoneApiError::NotFound {
                        resource: "domain".into(),
                        identifier: did.clone(),
                    })?,
            ),
        ),
        _ => (None, None),
    };
    let mut token = state.provider.get_token_provider().issue_token(
        user.id.clone(),
        Vec::from(["oidc".into()]),
        Vec::<String>::from([URL_SAFE
            .encode(Uuid::new_v4().as_bytes())
            .trim_end_matches('=')
            .to_string()]),
        project.as_ref(),
        domain.as_ref(),
    )?;

    state
        .provider
        .get_token_provider()
        .populate_role_assignments(&mut token, &state.db, &state.provider)
        .await
        .map_err(|_| KeystoneApiError::Forbidden)?;

    state
        .provider
        .get_token_provider()
        .expand_project_information(&mut token, &state.db, &state.provider)
        .await?;

    state
        .provider
        .get_token_provider()
        .expand_domain_information(&mut token, &state.db, &state.provider)
        .await?;

    let mut api_token = KeystoneTokenResponse {
        token: ApiResponseToken::from_user_auth(
            &state,
            &token,
            &user,
            project.as_ref(),
            domain.as_ref(),
        )
        .await?,
    };
    let catalog: Catalog = state
        .provider
        .get_catalog_provider()
        .get_catalog(&state.db, true)
        .await?
        .into();
    api_token.token.catalog = Some(catalog);

    debug!("response is {:?}", api_token);
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}

fn validate_bound_claims(
    mapping: &ProviderMapping,
    claims: &IdTokenClaims<AllOtherClaims, CoreGenderClaim>,
    claims_as_json: &Value,
) -> Result<(), OidcError> {
    if let Some(bound_subject) = &mapping.bound_subject {
        if bound_subject != claims.subject().as_str() {
            return Err(OidcError::BoundSubjectMismatch {
                expected: bound_subject.to_string(),
                found: claims.subject().as_str().into(),
            });
        }
    }
    if let Some(bound_audiences) = &mapping.bound_audiences {
        let mut bound_audiences_match: bool = false;
        for claim_audience in claims.audiences() {
            if bound_audiences.iter().any(|x| x == claim_audience.as_str()) {
                bound_audiences_match = true;
            }
        }
        if !bound_audiences_match {
            return Err(OidcError::BoundAudiencesMismatch {
                expected: bound_audiences.join(","),
                found: claims
                    .audiences()
                    .iter()
                    .map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }
    }
    if let Some(bound_claims) = &mapping.bound_claims {
        if let Some(required_claims) = bound_claims.as_object() {
            for (claim, value) in required_claims.iter() {
                if !claims_as_json
                    .get(claim)
                    .map(|x| x == value)
                    .is_some_and(|val| val)
                {
                    return Err(OidcError::BoundClaimsMismatch {
                        claim: claim.to_string(),
                        expected: value.to_string(),
                        found: claims_as_json
                            .get(claim)
                            .map(|x| x.to_string())
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn map_user_data(
    idp: &ProviderIdentityProvider,
    mapping: &ProviderMapping,
    claims_as_json: &Value,
) -> Result<MappedUserData, OidcError> {
    let mut builder = MappedUserDataBuilder::default();
    builder.unique_id(
        claims_as_json
            .get(&mapping.user_id_claim)
            .and_then(|x| x.as_str())
            .ok_or_else(|| OidcError::UserIdClaimMissing(mapping.user_id_claim.clone()))?,
    );

    builder.user_name(
        claims_as_json
            .get(&mapping.user_name_claim)
            .and_then(|x| x.as_str())
            .ok_or_else(|| OidcError::UserNameClaimMissing(mapping.user_name_claim.clone()))?,
    );

    builder.domain_id(
        mapping
            .domain_id
            .as_ref()
            .or(idp.domain_id.as_ref())
            .or(mapping
                .domain_id_claim
                .as_ref()
                .and_then(|claim| {
                    claims_as_json
                        .get(claim)
                        .and_then(|x| x.as_str().map(|v| v.to_string()))
                })
                .as_ref())
            .ok_or(OidcError::UserDomainUnbound)?,
    );

    Ok(builder.build()?)
}
