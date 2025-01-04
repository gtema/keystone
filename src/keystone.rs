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

use sea_orm::DatabaseConnection;
use std::sync::Arc;

use tracing::info;

use crate::config::Config;
use crate::error::KeystoneError;
use crate::identity::IdentitySrv;

#[derive()]
pub struct ServiceState {
    pub config: Config,
    pub identity: Arc<IdentitySrv>,
    pub db: DatabaseConnection,
}

impl ServiceState {
    pub async fn new(cfg: Config, db: DatabaseConnection) -> Result<Self, KeystoneError> {
        let identity = Arc::new(IdentitySrv::new(&cfg)?);

        Ok(Self {
            config: cfg.clone(),
            identity,
            db,
        })
    }

    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        Ok(())
    }
}
