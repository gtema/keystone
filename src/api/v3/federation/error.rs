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

use thiserror::Error;
use tracing::error;

use crate::api::v3::federation::types::*;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("discovery error")]
    Discovery { msg: String },

    #[error("Client without discovery is not supported")]
    ClientWithoutDiscoveryNotSupported,

    #[error(
        "Federated authentication requires mapping being specified in the payload or default set on the identity provider"
    )]
    MappingRequired,

    #[error("request token error")]
    RequestToken { msg: String },

    #[error("claim verification error")]
    ClaimVerification {
        #[from]
        source: openidconnect::ClaimsVerificationError,
    },

    #[error("error parsing the url")]
    UrlParse {
        #[from]
        source: url::ParseError,
    },

    #[error("server did not returned an ID token")]
    NoToken,

    #[error("ID token does not contain user id claim {0}")]
    UserIdClaimMissing(String),
    #[error("ID token does not contain user id claim {0}")]
    UserNameClaimMissing(String),
    #[error("can not identify resulting domain_id for the user")]
    UserDomainUnbound,

    #[error("bound subject mismatches {expected} != {found}")]
    BoundSubjectMismatch { expected: String, found: String },
    #[error("bound audiences mismatch {expected} != {found}")]
    BoundAudiencesMismatch { expected: String, found: String },
    #[error("bound claims mismatch")]
    BoundClaimsMismatch {
        claim: String,
        expected: String,
        found: String,
    },

    #[error(transparent)]
    MappedUserDataBuilder {
        #[from]
        source: MappedUserDataBuilderError,
    },
}

impl OidcError {
    pub fn discovery<T: std::error::Error>(fail: &T) -> Self {
        Self::Discovery {
            msg: fail.to_string(),
        }
    }
    pub fn request_token<T: std::error::Error>(fail: &T) -> Self {
        Self::RequestToken {
            msg: fail.to_string(),
        }
    }
    //    pub fn url(fail: url::ParseError) -> Self {
    //        Self::RequestToken {
    //            msg: fail.to_string(),
    //        }
    //    }

    //    pub fn claim_verification<T: std::error::Error>(fail: &T) -> Self {
    //        Self::ClaimVerification{msg: fail.to_string()}
    //    }
}

//impl
//    From<
//        openidconnect::DiscoveryError<
//            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
//        >,
//    > for OidcError
//{
//    fn from(
//        source: openidconnect::DiscoveryError<
//            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
//        >,
//    ) -> Self {
//        Self::OidcDiscovery {
//            msg: source.to_string(),
//        }
//    }
//}

//impl OidcError {
//    fn discovery(source: RE) -> Self {
//        Self::OidcDiscovery {
//            source: source.to_string(),
//        }
//    }
//}
