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

use std::num::TryFromIntError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenProviderError {
    /// IO error.
    #[error("io error: {}", source)]
    Io {
        /// The source of the error.
        #[from]
        source: std::io::Error,
    },

    /// Fernet Decryption
    #[error("fernet decryption error")]
    FernetDecryption {
        /// The source of the error.
        #[from]
        source: fernet::DecryptionError,
    },

    /// Missing fernet keys
    #[error("missing fernet keys")]
    FernetKeysMissing,

    /// Invalid token data
    #[error("invalid token error")]
    InvalidToken,

    /// Unsupported token version
    #[error("token version {0} is not supported")]
    InvalidTokenType(u8),
    ///
    /// Unsupported token uuid
    #[error("token uuid is not supported")]
    InvalidTokenUuid,

    /// Unsupported token uuid coding
    #[error("token uuid coding {0:?} is not supported")]
    InvalidTokenUuidMarker(rmp::Marker),

    /// Expired token
    #[error("token expired")]
    Expired,

    /// MSGPack Decryption
    #[error("rmp value error")]
    RmpValue {
        /// The source of the error.
        #[from]
        source: rmp::decode::ValueReadError,
    },

    #[error("uuid decryption error")]
    Uuid {
        /// The source of the error.
        #[from]
        source: uuid::Error,
    },

    #[error("int parse")]
    TryFromIntError {
        /// The source of the error.
        #[from]
        source: TryFromIntError,
    },
}
