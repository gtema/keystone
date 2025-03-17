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

use axum::extract::FromRef;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use tracing::info;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::Url};

use crate::config::Config;
use crate::error::KeystoneError;
use crate::provider::Provider;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection not implementing
// Clone
//#[derive(Clone)]
#[derive(FromRef)]
pub struct Service {
    pub config: Config,
    pub provider: Provider,
    #[from_ref(skip)]
    pub db: DatabaseConnection,
    pub webauthn: Webauthn,
}

pub type ServiceState = Arc<Service>;

impl Service {
    pub fn new(
        cfg: Config,
        db: DatabaseConnection,
        provider: Provider,
    ) -> Result<Self, KeystoneError> {
        // Effective domain name.
        let rp_id = "localhost";
        // Url containing the effective domain name
        // MUST include the port number!
        let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");

        // Now, with the builder you can define other options.
        // Set a "nice" relying party name. Has no security properties and
        // may be changed in the future.
        let builder = builder.rp_name("Keystone");

        // Consume the builder and create our webauthn instance.
        let webauthn = builder.build().expect("Invalid configuration");

        Ok(Self {
            config: cfg.clone(),
            provider,
            db,
            webauthn,
        })
    }

    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        Ok(())
    }
}
