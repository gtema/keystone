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

use std::collections::HashMap;

use crate::identity::types::IdentityBackend;
use crate::resource::types::ResourceBackend;

/// Plugin manager allowing to pass custom backend plugins implementing required trait during the
/// service start
#[derive(Clone, Debug, Default)]
pub struct PluginManager {
    /// Identity backend plugins
    identity_backends: HashMap<String, Box<dyn IdentityBackend>>,
    resource_backends: HashMap<String, Box<dyn ResourceBackend>>,
}

impl PluginManager {
    /// Register identity backend
    pub fn register_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Box<dyn IdentityBackend>,
    ) {
        self.identity_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Get registered identity backend
    #[allow(clippy::borrowed_box)]
    pub fn get_identity_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn IdentityBackend>> {
        self.identity_backends.get(name.as_ref())
    }

    /// Get registered resource backend
    #[allow(clippy::borrowed_box)]
    pub fn get_resource_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn ResourceBackend>> {
        self.resource_backends.get(name.as_ref())
    }
}
