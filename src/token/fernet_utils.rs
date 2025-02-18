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
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;
use tracing::trace;

use crate::token::error::TokenProviderError;

#[derive(Clone, Debug, Default)]
pub struct FernetUtils {
    pub key_repository: PathBuf,
    pub max_active_keys: usize,
}

impl FernetUtils {
    fn validate_key_repository(&self) -> Result<bool, TokenProviderError> {
        Ok(self.key_repository.exists())
    }

    pub async fn load_keys(&self) -> Result<impl IntoIterator<Item = String>, TokenProviderError> {
        let mut keys: BTreeMap<i8, String> = BTreeMap::new();
        if self.validate_key_repository()? {
            let mut entries = fs::read_dir(&self.key_repository).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Ok(fname) = entry.file_name().into_string() {
                    if let Ok(key_order) = fname.parse::<i8>() {
                        // We are only interested in files named as integer (0, 1, 2, ...)
                        trace!("Loading key from {:?}", entry.file_name());
                        let key = fs::read_to_string(entry.path()).await?;
                        keys.insert(key_order, key);
                    }
                }
            }
        }
        Ok(keys.into_values().rev())
    }
}

#[cfg(test)]
mod tests {
    use super::FernetUtils;
    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    #[tokio::test]
    async fn test_load_keys() {
        let tmp_dir = TempDir::new("example").unwrap();
        for i in 0..5 {
            let file_path = tmp_dir.path().join(format!("{}", i));
            let mut tmp_file = File::create(file_path).unwrap();
            write!(tmp_file, "{}", i).unwrap();
        }
        // write dummy file to check it is ignored
        let file_path = tmp_dir.path().join("dummy");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "foo").unwrap();

        let utils = FernetUtils {
            key_repository: tmp_dir.into_path(),
            ..Default::default()
        };
        let keys: Vec<String> = utils.load_keys().await.unwrap().into_iter().collect();

        assert_eq!(
            vec![
                "4".to_string(),
                "3".to_string(),
                "2".to_string(),
                "1".to_string(),
                "0".to_string()
            ],
            keys
        );
    }
}
