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

use std::cmp::max;
use tracing::warn;

use crate::config::{Config, PasswordHashingAlgo};
use crate::identity::error::IdentityProviderPasswordHashError;

fn verify_length_and_trunc_password(password: &[u8], max_length: usize) -> &[u8] {
    if password.len() > max_length {
        warn!("Truncating password to the specified value");
        return &password[..max_length];
    }
    password
}

pub fn hash_password<S: AsRef<[u8]>>(
    conf: &Config,
    password: S,
) -> Result<String, IdentityProviderPasswordHashError> {
    match conf.identity.password_hashing_algorithm {
        PasswordHashingAlgo::Bcrypt => {
            let password_bytes = verify_length_and_trunc_password(
                password.as_ref(),
                max(conf.identity.max_password_length, 72),
            );
            let rounds = conf.identity.password_hash_rounds.unwrap_or(12);
            Ok(bcrypt::hash(password_bytes, rounds as u32)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_verify_length_and_trunc_password() {
        assert_eq!(
            b"abcdefg",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 70)
        );
        assert_eq!(
            b"abcd",
            verify_length_and_trunc_password("abcdefg".as_bytes(), 4)
        );
        // In UTF8 bytes a single unicode is taking 3 bytes already
        assert_eq!(
            b"\xE2\x98\x81a",
            verify_length_and_trunc_password("☁abcdefg".as_bytes(), 4)
        );
    }

    #[test]
    fn test_hash_bcrypt() {
        let conf = Config::new(PathBuf::new()).unwrap();
        assert!(hash_password(&conf, "abcdefg").is_ok());
    }
}
