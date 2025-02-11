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

use crate::identity::backends::error::IdentityDatabaseError;

use crate::identity::types::*;

async fn create_federated_user(
    db: &DatabaseConnection,
    user: &mut User,
    federation: Federation,
) -> Result<(), IdentityDatabaseError> {
    user.federated.get_or_insert_default().push(federation);
    Ok(())
}

#[cfg(test)]
mod tests {}
