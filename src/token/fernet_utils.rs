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

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{DateTime, Utc};
use rmp::{Marker, decode::*, encode::*};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use tokio::fs as fs_async;
use tracing::trace;
use uuid::Uuid;

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

    pub fn load_keys(
        &self,
    ) -> Result<impl IntoIterator<Item = String> + use<>, TokenProviderError> {
        let mut keys: BTreeMap<i8, String> = BTreeMap::new();
        if self.validate_key_repository()? {
            for entry in fs::read_dir(&self.key_repository)? {
                let entry = entry?;
                if let Ok(fname) = entry.file_name().into_string() {
                    if let Ok(key_order) = fname.parse::<i8>() {
                        // We are only interested in files named as integer (0, 1, 2, ...)
                        trace!("Loading key from {:?}", entry.file_name());
                        let key = fs::read_to_string(entry.path())?;
                        keys.insert(key_order, key);
                    }
                }
            }
        }
        Ok(keys.into_values().rev())
    }
    pub async fn load_keys_async(
        &self,
    ) -> Result<impl IntoIterator<Item = String> + use<>, TokenProviderError> {
        let mut keys: BTreeMap<i8, String> = BTreeMap::new();
        if self.validate_key_repository()? {
            let mut entries = fs_async::read_dir(&self.key_repository).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Ok(fname) = entry.file_name().into_string() {
                    if let Ok(key_order) = fname.parse::<i8>() {
                        // We are only interested in files named as integer (0, 1, 2, ...)
                        trace!("Loading key from {:?}", entry.file_name());
                        let key = fs_async::read_to_string(entry.path()).await?;
                        keys.insert(key_order, key);
                    }
                }
            }
        }
        Ok(keys.into_values().rev())
    }
}

/// Read binary data from the payload
pub fn read_bin_data<R: Read>(len: u32, rd: &mut R) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(len.min(1 << 16) as usize);
    let bytes_read = rd.take(u64::from(len)).read_to_end(&mut buf)?;
    if bytes_read != len as usize {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(buf)
}

/// Read string data
pub fn read_str_data<R: Read>(len: u32, rd: &mut R) -> Result<String, io::Error> {
    Ok(String::from_utf8_lossy(&read_bin_data(len, rd)?).into_owned())
}

/// Read the UUID from the payload
/// It is represented as an Array[bool, bytes] where first bool indicates whether following bytes
/// are UUID or just bytes that should be treated as a string (for cases where ID is not a valid
/// UUID)
pub fn read_uuid(rd: &mut &[u8]) -> Result<String, TokenProviderError> {
    match read_marker(rd).map_err(ValueReadError::from)? {
        Marker::FixArray(_) => {
            match read_marker(rd).map_err(ValueReadError::from)? {
                Marker::True => {
                    // This is uuid as bytes
                    // Technically we may fail reading it into bytes, but python part is
                    // responsible that it doesn not happen
                    if let Marker::Bin8 = read_marker(rd).map_err(ValueReadError::from)? {
                        return Ok(Uuid::try_from(read_bin_data(read_pfix(rd)?.into(), rd)?)?
                            .as_simple()
                            .to_string());
                    }
                    println!("1");
                }
                Marker::False => {
                    // This is not uuid
                    match read_marker(rd).map_err(ValueReadError::from)? {
                        Marker::Bin8 => {
                            return Ok(String::from_utf8_lossy(&read_bin_data(
                                read_pfix(rd)?.into(),
                                rd,
                            )?)
                            .to_string());
                        }
                        Marker::FixStr(len) => {
                            return Ok(read_str_data(len.into(), rd)?);
                        }
                        other => {
                            return Err(TokenProviderError::InvalidTokenUuidMarker(other));
                        }
                    }
                }
                other => {
                    return Err(TokenProviderError::InvalidTokenUuidMarker(other));
                }
            }
        }
        Marker::FixStr(len) => {
            return Ok(read_str_data(len.into(), rd)?);
        }
        other => {
            return Err(TokenProviderError::InvalidTokenUuidMarker(other));
        }
    }
    println!("here");
    Err(TokenProviderError::InvalidTokenUuid)
}

/// Write the UUID to the payload
/// It is represented as an Array[bool, bytes] where first bool indicates whether following bytes
/// are UUID or just bytes that should be treated as a string (for cases where ID is not a valid
/// UUID)
pub fn write_uuid<W: RmpWrite>(wd: &mut W, uid: &str) -> Result<(), TokenProviderError> {
    match Uuid::parse_str(uid) {
        Ok(uuid) => {
            write_array_len(wd, 2).map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
            write_bool(wd, true).map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
            write_bin(wd, uuid.as_bytes())
                .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
        }
        _ => {
            write_array_len(wd, 2).map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
            write_bool(wd, false).map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
            write_bin(wd, uid.as_bytes())
                .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
        }
    }
    Ok(())
}

/// Read the time represented as a f64 of the UTC seconds
pub fn read_time(rd: &mut &[u8]) -> Result<DateTime<Utc>, TokenProviderError> {
    DateTime::from_timestamp(read_f64(rd)?.round() as i64, 0)
        .ok_or(TokenProviderError::InvalidToken)
}

/// Write the time represented as a f64 of the UTC seconds
pub fn write_time<W: RmpWrite>(wd: &mut W, time: DateTime<Utc>) -> Result<(), TokenProviderError> {
    write_f64(wd, time.timestamp() as f64)
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
    Ok(())
}

/// Decode array of audit ids from the payload
pub fn read_audit_ids(
    rd: &mut &[u8],
) -> Result<impl IntoIterator<Item = String> + use<>, TokenProviderError> {
    if let Marker::FixArray(len) = read_marker(rd).map_err(ValueReadError::from)? {
        let mut result: Vec<String> = Vec::new();
        for _ in 0..len {
            if let Marker::Bin8 = read_marker(rd).map_err(ValueReadError::from)? {
                let dt = read_bin_data(read_pfix(rd)?.into(), rd)?;
                let audit_id: String = URL_SAFE.encode(dt).trim_end_matches('=').to_string();
                result.push(audit_id);
            } else {
                return Err(TokenProviderError::InvalidToken);
            }
        }
        return Ok(result.into_iter());
    }
    Err(TokenProviderError::InvalidToken)
}

/// Encode array of audit ids into the payload
pub fn write_audit_ids<W: RmpWrite, I: IntoIterator<Item = String>>(
    wd: &mut W,
    data: I,
) -> Result<(), TokenProviderError> {
    let vals = Vec::from_iter(data.into_iter().map(|mut x| {
        x.push_str("==");
        x
    }));
    write_array_len(wd, vals.len() as u32)
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
    for val in vals.iter() {
        write_bin(wd, &URL_SAFE.decode(val)?)
            .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
    }
    Ok(())
}

/// Decode array of strings ids from the payload
pub fn read_list_of_uuids(
    rd: &mut &[u8],
) -> Result<impl IntoIterator<Item = String> + use<>, TokenProviderError> {
    if let Marker::FixArray(len) = read_marker(rd).map_err(ValueReadError::from)? {
        let mut result: Vec<String> = Vec::new();
        for _ in 0..len {
            result.push(read_uuid(rd)?);
        }
        return Ok(result.into_iter());
    }
    Err(TokenProviderError::InvalidToken)
}

/// Encode array of bytes into the payload
pub fn write_list_of_uuids<W: RmpWrite, I: IntoIterator<Item = V>, V: AsRef<str>>(
    wd: &mut W,
    data: I,
) -> Result<(), TokenProviderError> {
    let vals = Vec::from_iter(data);
    write_array_len(wd, vals.len() as u32)
        .map_err(|x| TokenProviderError::RmpEncode(x.to_string()))?;
    for val in vals.iter() {
        write_uuid(wd, val.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::FernetUtils;
    use chrono::{Local, SubsecRound};
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn test_load_keys() {
        let tmp_dir = tempdir().unwrap();
        for i in 0..5 {
            let file_path = tmp_dir.path().join(format!("{i}"));
            let mut tmp_file = File::create(file_path).unwrap();
            write!(tmp_file, "{i}").unwrap();
        }
        // write dummy file to check it is ignored
        let file_path = tmp_dir.path().join("dummy");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "foo").unwrap();

        let utils = FernetUtils {
            key_repository: tmp_dir.keep(),
            ..Default::default()
        };
        let keys: Vec<String> = utils.load_keys_async().await.unwrap().into_iter().collect();

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

    #[test]
    fn test_write_read_uuid_str() {
        let mut buf = Vec::with_capacity(36);
        let uuid = "abc";
        write_uuid(&mut buf, uuid).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_uuid(&mut decode_data).unwrap();
        assert_eq!(uuid, decoded);
    }

    #[test]
    fn test_write_read_uuid() {
        let mut buf = Vec::with_capacity(36);
        let test = Uuid::new_v4();
        write_uuid(&mut buf, &test.to_string()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_uuid(&mut decode_data).unwrap();
        assert_eq!(test.simple().to_string(), decoded);
    }

    #[test]
    fn test_write_read_time() {
        let test = Local::now().trunc_subsecs(0);
        let mut buf = Vec::with_capacity(36);
        write_time(&mut buf, test.into()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded = read_time(&mut decode_data).unwrap();
        assert_eq!(test, decoded);
    }

    #[test]
    fn test_write_audit_ids() {
        let test = vec!["Zm9vCg".into()];
        let mut buf = Vec::with_capacity(36);
        write_audit_ids(&mut buf, test.clone()).unwrap();
        let msg = buf.clone();
        let mut decode_data = msg.as_slice();
        let decoded: Vec<String> = read_audit_ids(&mut decode_data)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(test, decoded);
    }
}
