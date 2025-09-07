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

//! Embedded type webauthn-rs::auth::PublickeyCredentialRequest.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PasskeyAuthenticationStartRequest {
    /// The ID of the user that is trying to authenticate
    pub user_id: String,
}
/// Passkey Authorization challenge.
///
/// This is an embedded version of the
/// [webauthn-rs::auth::PublickeyCredentialRequest](https://docs.rs/webauthn-rs-proto/0.5.2/webauthn_rs_proto/auth/struct.PublicKeyCredentialRequestOptions.html)
///
/// A JSON serializable challenge which is issued to the user’s webbrowser for handling. This is
/// meant to be opaque, that is, you should not need to inspect or alter the content of the struct
/// - you should serialise it and transmit it to the client only.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PasskeyAuthenticationStartResponse {
    /// The options.
    pub public_key: PublicKeyCredentialRequestOptions,
    /// The mediation requested.
    pub mediation: Option<Mediation>,
}

/// The requested options for the authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PublicKeyCredentialRequestOptions {
    /// The challenge that should be signed by the authenticator.
    pub challenge: Base64UrlSafeData,
    /// The timeout for the authenticator in case of no interaction.
    pub timeout: Option<u32>,
    /// The relying party ID.
    pub rp_id: String,
    /// The set of credentials that are allowed to sign this challenge.
    pub allow_credentials: Vec<AllowCredentials>,
    /// The verification policy the browser will request.
    pub user_verification: UserVerificationPolicy,
    /// Hints defining which types credentials may be used in this operation.
    pub hints: Option<Vec<PublicKeyCredentialHints>>,
    /// extensions.
    pub extensions: Option<RequestAuthenticationExtensions>,
}

/// Request in residentkey workflows that conditional mediation should be used in the UI, or not.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum Mediation {
    /// Discovered credentials are presented to the user in a dialog. Conditional UI is used. See https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI https://w3c.github.io/webappsec-credential-management/#enumdef-credentialmediationrequirement
    Conditional,
}

/// A descriptor of a credential that can be used.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AllowCredentials {
    /// The type of credential.
    pub type_: String,
    /// The id of the credential.
    pub id: Base64UrlSafeData,
    /// https://www.w3.org/TR/webauthn/#transport may be usb, nfc, ble, internal
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AuthenticatorTransport {
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb
    Usb,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc
    Nfc,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble
    Ble,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal
    Internal,
    /// Hybrid transport, formerly caBLE. Part of the level 3 draft specification. https://w3c.github.io/webauthn/#dom-authenticatortransport-hybrid
    Hybrid,
    /// Test transport; used for Windows 10.
    Test,
    /// An unknown transport was provided - it will be ignored.
    Unknown,
}

/// Defines the User Authenticator Verification policy. This is documented https://w3c.github.io/webauthn/#enumdef-userverificationrequirement, and each variant lists it’s effects.
///
/// To be clear, Verification means that the Authenticator perform extra or supplementary
/// interaction with the user to verify who they are. An example of this is Apple Touch Id required
/// a fingerprint to be verified, or a yubico device requiring a pin in addition to a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin where touch is the only
/// interaction - we only verify a user is present, but we don’t have extra details to the
/// legitimacy of that user.
///
/// As UserVerificationPolicy is only used in credential registration, this stores the verification
/// state of the credential in the persisted credential. These persisted credentials define which
/// UserVerificationPolicy is issued during authentications.
///
/// IMPORTANT - Due to limitations of the webauthn specification, CTAP devices, and browser
/// implementations, the only secure choice as an RP is required.
///
///   ⚠️ WARNING - discouraged is marked with a warning, as some authenticators will FORCE
///   verification during registration but NOT during authentication. This makes it impossible
///   for a relying party to consistently enforce user verification, which can confuse users and
///   lead them to distrust user verification is being enforced.
///
///   ⚠️ WARNING - preferred can lead to authentication errors in some cases due to browser
///   peripheral exchange allowing authentication verification bypass. Webauthn RS is not
///   vulnerable to these bypasses due to our tracking of UV during registration through
///   authentication, however preferred can cause legitimate credentials to not prompt for UV
///   correctly due to browser perhipheral exchange leading Webauthn RS to deny them in what
///   should otherwise be legitimate operations.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum UserVerificationPolicy {
    /// Require user verification bit to be set, and fail the registration or authentication if
    /// false. If the authenticator is not able to perform verification, it will not be usable with
    /// this policy.
    ///
    /// This policy is the default as it is the only secure and consistent user verification
    /// option.
    Required,
    /// Prefer UV if possible, but ignore if not present. In other webauthn deployments this is
    /// bypassable as it implies the library will not check UV is set correctly for this
    /// credential. Webauthn-RS is not vulnerable to this as we check the UV state always based on
    /// it’s presence at registration.
    ///
    /// However, in some cases use of this policy can lead to some credentials failing to verify
    /// correctly due to browser peripheral exchange bypasses.
    Preferred,
}

/// A hint as to the class of device that is expected to fufil this operation.
///
/// https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhints
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum PublicKeyCredentialHints {
    /// The credential is a removable security key.
    SecurityKey,
    /// The credential is a platform authenticator.
    ClientDevice,
    /// The credential will come from an external device.
    Hybrid,
}

/// Extension option inputs for PublicKeyCredentialRequestOptions
///
/// Implements [AuthenticatorExtensionsClientInputs] from the spec
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RequestAuthenticationExtensions {
    /// The appid extension options.
    pub appid: Option<String>,
    /// ⚠️ - Browsers do not support this! Uvm.
    pub uvm: Option<bool>,
    /// ⚠️ - Browsers do not support this!
    /// https://bugs.chromium.org/p/chromium/issues/detail?id=1023225 Hmac get secret.
    pub hmac_get_secret: Option<HmacGetSecretInput>,
}

/// The inputs to the hmac secret if it was created during registration.
///
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct HmacGetSecretInput {
    /// Retrieve a symmetric secrets from the authenticator with this input.
    pub output1: Base64UrlSafeData,
    /// Rotate the secret in the same operation.
    pub output2: Option<Base64UrlSafeData>,
}

/// Serde wrapper for Vec<u8> which always emits URL-safe, non-padded Base64, and accepts Base64
/// and binary formats.
///
///   Serialisation always emits URL-safe, non-padded Base64 (per RFC 4648 §5).
///
///   Unlike HumanBinaryData, this happens regardless of whether the underlying serialisation
///   format is human readable. If you’re serialising to non-human-readable formats, you should
///   consider migrating to HumanBinaryData.
///
/// Otherwise, this type should work as much like a Vec<u8> as possible.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Base64UrlSafeData(Vec<u8>);

/// A client response to an authentication challenge. This contains all required information to
/// asses and assert trust in a credentials legitimacy, followed by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you should provide this to
/// the correctly handling function of Webauthn only.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PasskeyAuthenticationFinishRequest {
    /// The ID of the user.
    pub user_id: String,
    /// The credential Id, likely base64.
    pub id: String,
    /// The binary of the credential id.
    pub raw_id: Base64UrlSafeData,
    /// The authenticator response.
    pub response: AuthenticatorAssertionResponseRaw,
    /// Unsigned Client processed extensions.
    pub extensions: AuthenticationExtensionsClientOutputs,
    /// The authenticator type.
    pub type_: String,
}

/// [AuthenticatorAssertionResponseRaw](https://w3c.github.io/webauthn/#authenticatorassertionresponse)
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthenticatorAssertionResponseRaw {
    /// Raw authenticator data.
    pub authenticator_data: Base64UrlSafeData,
    /// Signed client data.
    pub client_data_json: Base64UrlSafeData,
    /// Signature.
    pub signature: Base64UrlSafeData,
    /// Optional userhandle.
    pub user_handle: Option<Base64UrlSafeData>,
}

/// [AuthenticationExtensionsClientOutputs](https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs)
///
/// The default option here for Options are None, so it can be derived
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthenticationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension.
    pub appid: Option<bool>,
    /// The response to a hmac get secret request.
    pub hmac_get_secret: Option<HmacGetSecretOutput>,
}

/// The response to a hmac get secret request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct HmacGetSecretOutput {
    /// Output of HMAC(Salt 1 || Client Secret).
    pub output1: Base64UrlSafeData,
    /// Output of HMAC(Salt 2 || Client Secret).
    pub output2: Option<Base64UrlSafeData>,
}
