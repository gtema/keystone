use axum::Router;
use sea_orm::ConnectOptions;
use sea_orm::Database;
use std::env;
use std::io;
use std::io::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{filter, prelude::*};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tracing;

use keystone::api;
use keystone::config::Config;
use keystone::keystone::ServiceState;

#[tokio::main]
async fn main() -> Result<(), Error> {
    //let stdout_log = tracing_subscriber::fmt::layer().with_writer(io::stdout);
    //tracing_subscriber::registry().with(stdout_log.with_filter(filter::LevelFilter::TRACE));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .init();

    let cfg =
        Config::new("/home/gtema/workspace/opendev/openstack/keystone/etc/keystone.conf".into());
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let mut opt = ConnectOptions::new(db_url.to_owned());
    opt.sqlx_logging(true) // Disable SQLx log
//        .sqlx_logging_level(log::LevelFilter::Info)
    ; // Or set SQLx log level

    let conn = Database::connect(db_url)
        .await
        .expect("Database connection failed");

    let shared_state = Arc::new(ServiceState::new(cfg, conn));

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api::ApiDoc::openapi()))
        .merge(api::router())
        .with_state(shared_state);

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await

    //println!("Config is {:?}", cfg);

    //let service = KeystoneService::new(&cfg);

    //println!(
    //    "Users {:?}",
    //    service
    //        .identity
    //        .list_users(&UserListParameters {}, &service.resource)
    //        .await
    //);
}
