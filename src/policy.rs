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

#[cfg(test)]
use mockall::mock;
use opa_wasm::{
    Runtime,
    wasmtime::{Config, Engine, Module, OptLevel, Store},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tracing::{Level, debug};

use crate::token::Token;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("{}", .0.violations.as_ref().map(
        |v| v.iter().cloned().map(|x| x.msg)
        .reduce(|acc, s| format!("{acc}, {s}"))
        .unwrap_or_default()
    ).unwrap_or("The request you made requires authentication.".into()))]
    Forbidden(PolicyEvaluationResult),

    #[error("module compilation task crashed")]
    Compilation(#[from] eyre::Report),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Json serializaion error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Wasm(#[from] opa_wasm::wasmtime::Error),
}

#[derive(Default)]
pub struct PolicyFactory {
    engine: Option<Engine>,
    module: Option<Module>,
}

impl PolicyFactory {
    #[tracing::instrument(name = "policy.from_defaults", err)]
    pub async fn from_defaults() -> Result<Self, PolicyError> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.wasm");
        let file = tokio::fs::File::open(path).await?;
        PolicyFactory::load(file).await
    }

    #[tracing::instrument(name = "policy.from_wasm", err)]
    pub async fn from_wasm(path: &Path) -> Result<Self, PolicyError> {
        let file = tokio::fs::File::open(path).await?;
        PolicyFactory::load(file).await
    }

    #[tracing::instrument(name = "policy.load", skip(source), err)]
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
    ) -> Result<Self, PolicyError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(OptLevel::SpeedAndSize);

        let engine = Engine::new(&config)?;

        // Read and compile the module
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).await?;
        // Compilation is CPU-bound, so spawn that in a blocking task
        let (engine, module) = tokio::task::spawn_blocking(move || {
            let module = Module::new(&engine, buf).map_err(PolicyError::from)?;
            Ok((engine, module))
        })
        .await?
        .map_err(PolicyError::Compilation)?;

        let factory = Self {
            engine: Some(engine),
            module: Some(module),
        };

        // Try to instantiate
        factory.instantiate().await?;

        Ok(factory)
    }

    #[tracing::instrument(name = "policy.instantiate", level = Level::TRACE, skip_all, err)]
    pub async fn instantiate(&self) -> Result<Policy, PolicyError> {
        if let (Some(engine), Some(module)) = (&self.engine, &self.module) {
            let mut store = Store::new(engine, ());
            let runtime = Runtime::new(&mut store, module).await?;

            let instance = runtime.without_data(&mut store).await?;
            Ok(Policy {
                store: Some(store),
                instance: Some(instance),
            })
        } else {
            Ok(Policy {
                store: None,
                instance: None,
            })
        }
    }
}

#[cfg(test)]
mock! {
    pub Policy {
        pub async fn enforce(
            &mut self,
            policy_name: &str,
            credentials: &Token,
            target: Value,
            current: Option<Value>
        ) -> Result<PolicyEvaluationResult, PolicyError>;
    }
}

#[cfg(test)]
mock! {
    pub PolicyFactory {
        pub async fn instantiate(&self) -> Result<MockPolicy, PolicyError>;
    }
}

pub struct Policy {
    store: Option<Store<()>>,
    instance: Option<opa_wasm::Policy<opa_wasm::DefaultContext>>,
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] eyre::Report),
}

/// OpenPolicyAgent `Credentials` object
#[derive(Serialize, Debug)]
pub struct Credentials {
    pub user_id: String,
    pub roles: Vec<String>,
    pub project_id: Option<String>,
    pub domain_id: Option<String>,
}

impl From<&Token> for Credentials {
    fn from(token: &Token) -> Self {
        Self {
            user_id: token.user_id().clone(),
            roles: token
                .roles()
                .map(|x| x.iter().map(|role| role.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default(),
            project_id: token.project().map(|val| val.id.clone()),
            domain_id: token.domain().map(|val| val.id.clone()),
        }
    }
}

impl Policy {
    #[tracing::instrument(
        name = "policy.evaluate",
        skip_all,
        fields(
            entrypoint = policy_name.as_ref(),
            input,
            result,
        ),
        err,
        level = Level::DEBUG
    )]
    pub async fn enforce<P: AsRef<str>>(
        &mut self,
        policy_name: P,
        credentials: impl Into<Credentials>,
        target: Value,
        update: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError> {
        let creds: Credentials = credentials.into();
        let input = json!({
            "credentials": creds,
            "target": target,
            "update": update,
        });

        if let (Some(store), Some(instance)) = (&mut self.store, &self.instance) {
            tracing::Span::current().record("input", serde_json::to_string(&input)?);
            let [res]: [OpaResponse; 1] = instance
                .evaluate(store, policy_name.as_ref(), &input)
                .await?;
            tracing::Span::current().record("result", serde_json::to_string(&res.result)?);
            debug!("authorized={}", res.result.allow());
            if !res.result.allow() {
                return Err(PolicyError::Forbidden(res.result));
            }

            Ok(res.result)
        } else {
            debug!("not enforcing policy due to the absence of initialized WASM data");
            Ok(PolicyEvaluationResult {
                allow: true,
                violations: None,
            })
        }
    }
}

/// A single violation of a policy.
#[derive(Clone, Deserialize, Debug, JsonSchema, Serialize)]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

/// The OpenPolicyAgent response.
#[derive(Deserialize, Debug)]
pub struct OpaResponse {
    pub result: PolicyEvaluationResult,
}

/// The result of a policy evaluation.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct PolicyEvaluationResult {
    pub allow: bool,
    #[serde(rename = "violation")]
    pub violations: Option<Vec<Violation>>,
}

impl std::fmt::Display for PolicyEvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        if let Some(violations) = &self.violations {
            for violation in violations {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "{}", violation.msg)?;
            }
        }
        Ok(())
    }
}

impl PolicyEvaluationResult {
    #[must_use]
    pub fn allow(&self) -> bool {
        self.allow
    }

    /// Returns true if the policy evaluation was successful.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations
            .as_deref()
            .map(|x| x.is_empty())
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            violations: None,
        }
    }

    #[cfg(test)]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            violations: None,
        }
    }
}
