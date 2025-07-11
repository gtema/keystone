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

pub mod api;
pub mod assignment;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod db;
pub mod db_migration;
pub mod error;
pub mod federation;
pub mod identity;
pub mod keystone;
pub mod plugin_manager;
pub mod policy;
pub mod provider;
pub mod resource;
pub mod token;

#[cfg(test)]
mod tests;
