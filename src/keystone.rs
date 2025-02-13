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
//use tokio::sync::RwLock;

use tracing::info;

use crate::config::Config;
use crate::error::KeystoneError;
use crate::provider::Provider;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection not implementing
// Clone
//#[derive(Clone)]
pub struct ServiceState<P> {
    pub config: Config,
    pub provider: P,
    pub db: DatabaseConnection,
}

impl<P> ServiceState<P>
where
    P: Provider,
{
    pub fn new(cfg: Config, db: DatabaseConnection, provider: P) -> Result<Self, KeystoneError> {
        Ok(Self {
            config: cfg.clone(),
            provider,
            db,
        })
    }

    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        Ok(())
    }
}
