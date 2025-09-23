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

//! JWT based authentication API

use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    http::header::AUTHORIZATION,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use tracing::warn;
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::{
    CoreClient, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::reqwest;
use openidconnect::{
    AdditionalClaims, Client, ClientId, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeySet,
    JsonWebKeySetUrl, Nonce,
};

use crate::api::common::find_project_from_scope;
use crate::api::v4::auth::token::types::{
    Token as ApiResponseToken, TokenResponse as KeystoneTokenResponse,
};
use crate::api::v4::federation::error::OidcError;
use crate::api::v4::federation::types::*;
use crate::api::{Catalog, error::KeystoneApiError};
use crate::auth::{AuthenticatedInfo, AuthenticationError, AuthzInfo};
use crate::catalog::CatalogApi;
use crate::federation::FederationApi;
use crate::federation::types::{
    MappingListParameters as ProviderMappingListParameters, MappingType as ProviderMappingType,
    Project as ProviderProject, Scope as ProviderScope,
    identity_provider::IdentityProvider as ProviderIdentityProvider,
    mapping::Mapping as ProviderMapping,
};
use crate::identity::IdentityApi;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{FederationBuilder, FederationProtocol, UserCreateBuilder};
use crate::keystone::ServiceState;
use crate::token::TokenApi;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(login))
}

#[derive(Debug, Deserialize, Serialize)]
struct AllOtherClaims(HashMap<String, serde_json::Value>);
impl AdditionalClaims for AllOtherClaims {}

type FullIdToken = IdToken<
    AllOtherClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// Prepare the proper scope.
///
/// # Arguments
/// * `state`: The service state
/// * `scope`: The scope to extract the AuthZ information from
///
/// # Returns
/// * `AuthzInfo`: The AuthZ information
/// * `KeystoneApiError`: An error if the scope is not valid
async fn get_authz_info(
    state: &ServiceState,
    scope: Option<ProviderScope>,
) -> Result<AuthzInfo, KeystoneApiError> {
    let authz_info = match scope {
        Some(ProviderScope::Project(scope)) => {
            if let Some(project) = find_project_from_scope(state, &scope.into()).await? {
                AuthzInfo::Project(project)
            } else {
                return Err(KeystoneApiError::Unauthorized);
            }
        }
        _ => AuthzInfo::Unscoped,
    };
    authz_info.validate()?;
    Ok(authz_info)
}

/// Authentication using the JWT.
///
/// This operation allows user to exchange the JWT issued by the trusted identity provider for the
/// regular Keystone session token. Request specifies the necessary authentication mapping, which
/// is also used to validate expected claims.
#[utoipa::path(
    post,
    //path = "/jwt/login",
    path = "/identity_providers/{idp_id}/jwt",
    operation_id = "/federation/identity_provider/jwt:login",
    params(
        ("openstack-mapping" = String, Header, description = "Federated attribute mapping"),

    ),
    responses(
        (status = OK, description = "Authentication Token object", body = KeystoneTokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        ),
    ),
    ),
    security(("jwt" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_jwt_login",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn login(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Path(idp_id): Path<String>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .config
        .auth
        .methods
        .iter()
        // TODO: is it how it should be hardcoded?
        // TODO: should be better to use jwt, but it is not available in py-keystone
        .find(|m| *m == "openid")
        .ok_or(KeystoneApiError::AuthMethodNotSupported)?;

    let jwt: String = match headers
        .get(AUTHORIZATION)
        .ok_or(KeystoneApiError::SubjectTokenMissing)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .split_once(' ')
    {
        Some(("bearer", token)) => token.to_string(),
        _ => return Err(OidcError::BearerJwtTokenMissing.into()),
    };

    let mapping: String = headers
        .get("openstack-mapping")
        .ok_or(OidcError::MappingRequiredJwt)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .to_string();

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state.db, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id.clone(),
            })
        })??;

    let mapping = state
        .provider
        .get_federation_provider()
        .list_mappings(
            &state.db,
            &ProviderMappingListParameters {
                idp_id: Some(idp_id.clone()),
                name: Some(mapping.clone()),
                r#type: Some(ProviderMappingType::Jwt),
                ..Default::default()
            },
        )
        .await?
        .first()
        .ok_or(KeystoneApiError::NotFound {
            resource: "mapping".into(),
            identifier: mapping.clone(),
        })?
        .to_owned();

    //if !matches!(mapping.r#type, ProviderMappingType::Jwt) {
    //    // need to log helping message, since the error is wrapped
    //    // to prevent existence exposure.
    //    warn!("Not JWT mapping used for the JWT login");
    //    return Err(OidcError::NonJwtMapping)?;
    //}

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(OidcError::from)?;

    // Discover metadata when issuer or jwks_url is not known
    let provider_metadata: Option<CoreProviderMetadata> = if let Some(discovery_url) =
        &idp.oidc_discovery_url
        && (idp.bound_issuer.is_none() || idp.jwks_url.is_none())
    {
        Some(
            CoreProviderMetadata::discover_async(
                IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
                &http_client,
            )
            .await
            .map_err(|err| OidcError::discovery(&err))?,
        )
    } else {
        None
    };

    let issuer_url = if let Some(bound_issuer) = &idp.bound_issuer {
        IssuerUrl::new(bound_issuer.clone()).map_err(OidcError::from)?
    } else if let Some(metadata) = &provider_metadata {
        metadata.issuer().clone()
    } else {
        warn!("No issuer_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer)?;
    };

    let jwks_url = if let Some(jwks_url) = &idp.jwks_url {
        JsonWebKeySetUrl::new(jwks_url.clone()).map_err(OidcError::from)?
    } else if let Some(metadata) = &provider_metadata {
        metadata.jwks_uri().clone()
    } else {
        warn!("No jwks_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer)?;
    };

    let jwks: JsonWebKeySet<CoreJsonWebKey> = JsonWebKeySet::fetch_async(&jwks_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(&err))?;

    // TODO: client_id should match the audience. How to get that?
    let audience = "keystone";
    let client: CoreClient = Client::new(ClientId::new(audience.to_string()), issuer_url, jwks);

    let id_token = FullIdToken::from_str(&jwt)?;

    let id_token_verifier = client.id_token_verifier().require_audience_match(false);
    // The nonce is not used in the JWT flow, so we can ignore it.
    let nonce_verifier = |_nonce: Option<&Nonce>| Ok(());
    let claims = id_token
        .into_claims(&id_token_verifier, &nonce_verifier)
        .map_err(OidcError::from)?;

    let claims_as_json = serde_json::to_value(&claims)?;

    validate_bound_claims(&mapping, &claims, &claims_as_json)?;
    let mapped_user_data = map_user_data(&state, &idp, &mapping, &claims_as_json).await?;

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
        federated_user.idp_id(idp.id.clone());
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
    let authed_info = AuthenticatedInfo::builder()
        .user_id(user.id.clone())
        .user(user.clone())
        .methods(vec!["openid".into()])
        .idp_id(idp.id.clone())
        .protocol_id("jwt".to_string())
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    // TODO: detect scope from the mapping or claims
    let authz_info = get_authz_info(
        &state,
        mapping.token_project_id.as_ref().map(|token_project_id| {
            ProviderScope::Project(ProviderProject {
                id: Some(token_project_id.to_string()),
                ..Default::default()
            })
        }),
    )
    .await?;

    let mut token = state
        .provider
        .get_token_provider()
        .issue_token(authed_info, authz_info)?;

    // TODO: roles should be granted for the jwt login already

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&token, &state.db, &state.provider)
        .await
        .map_err(|_| KeystoneApiError::Forbidden)?;

    let mut api_token = KeystoneTokenResponse {
        token: ApiResponseToken::from_provider_token(&state, &token).await?,
    };
    let catalog: Catalog = state
        .provider
        .get_catalog_provider()
        .get_catalog(&state.db, true)
        .await?
        .into();
    api_token.token.catalog = Some(catalog);

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

/// Validate bound claims in the token
///
/// # Arguments
///
/// * `mapping` - The mapping to validate against
/// * `claims` - The claims to validate
/// * `claims_as_json` - The claims as json to validate
///
/// # Returns
///
/// * `Result<(), OidcError>`
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

/// Map the user data using the referred mapping
///
/// # Arguments
/// * `idp` - The identity provider
/// * `mapping` - The mapping to use
/// * `claims_as_json` - The claims as json
///
/// # Returns
/// The mapped user data
async fn map_user_data(
    state: &ServiceState,
    idp: &ProviderIdentityProvider,
    mapping: &ProviderMapping,
    claims_as_json: &Value,
) -> Result<MappedUserData, OidcError> {
    let mut builder = MappedUserDataBuilder::default();
    if let Some(token_user_id) = &mapping.token_user_id {
        // TODO: How to check that the user belongs to the right domain)
        if let Ok(Some(user)) = state
            .provider
            .get_identity_provider()
            .get_user(&state.db, token_user_id)
            .await
        {
            builder.unique_id(token_user_id.clone());
            builder.user_name(user.name.clone());
        } else {
            return Err(OidcError::UserNotFound(token_user_id.clone()))?;
        }
    } else {
        builder.unique_id(
            claims_as_json
                .get(&mapping.user_id_claim)
                .and_then(|x| x.as_str())
                .ok_or_else(|| OidcError::UserIdClaimRequired(mapping.user_id_claim.clone()))?
                .to_string(),
        );

        builder.user_name(
            claims_as_json
                .get(&mapping.user_name_claim)
                .and_then(|x| x.as_str())
                .ok_or_else(|| OidcError::UserNameClaimRequired(mapping.user_name_claim.clone()))?,
        );
    }

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
