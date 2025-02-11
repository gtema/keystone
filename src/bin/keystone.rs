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

use axum::{extract::MatchedPath, http::Request};
use clap::Parser;
use color_eyre::eyre::{Report, Result};
use sea_orm::ConnectOptions;
use sea_orm::Database;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{info_span, Level};
use tracing_subscriber::{filter::LevelFilter, prelude::*};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use openstack_keystone::api;
use openstack_keystone::config::Config;
use openstack_keystone::keystone::ServiceState;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the keystone config file
    #[arg(short, long)]
    config: String,

    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, global=true, action = clap::ArgAction::Count, display_order = 920)]
    pub verbose: u8,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let args = Args::parse();

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(match args.verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        });

    // build the tracing registry
    tracing_subscriber::registry().with(log_layer).init();

    let cfg = Config::new(args.config.into())?;
    let db_url = cfg.database.get_connection();
    let mut opt = ConnectOptions::new(db_url.to_owned());
    if args.verbose < 2 {
        opt.sqlx_logging(false);
    }

    let conn = Database::connect(opt)
        .await
        .expect("Database connection failed");

    let shared_state = Arc::new(ServiceState::new(cfg, conn).await.unwrap());

    let (router, api) = OpenApiRouter::with_openapi(api::ApiDoc::openapi())
        .merge(api::router())
        .split_for_parts();

    let app = router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(
            ServiceBuilder::new().layer(
                TraceLayer::new_for_http()
                    .make_span_with(|request: &Request<_>| {
                        let matched_path = request
                            .extensions()
                            .get::<MatchedPath>()
                            .map(MatchedPath::as_str);

                        info_span!(
                            "http_request",
                            method = ?request.method(),
                            matched_path,
                            some_other_field = tracing::field::Empty,
                            uri = ?request.uri().path()
                        )
                    })
                    .on_request(DefaultOnRequest::new().level(Level::INFO))
                    .on_response(
                        DefaultOnResponse::new()
                            .level(Level::INFO)
                            .latency_unit(LatencyUnit::Micros),
                    ),
            ),
        )
        .with_state(shared_state.clone());

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    Ok(axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(shared_state.clone()))
        .await?)
}

async fn shutdown_signal(state: Arc<ServiceState>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {state.terminate().await.unwrap();},
        _ = terminate => {state.terminate().await.unwrap();},
    }
}
