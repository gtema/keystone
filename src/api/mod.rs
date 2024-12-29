use axum::Router;
use std::sync::Arc;
use utoipa::OpenApi;

use crate::keystone::ServiceState;

pub mod v3;

#[derive(OpenApi)]
#[openapi(
    info(version = "3.14.0"),
    nest(
        (path = "/v3", api = v3::V3Api)
    )
)]
pub struct ApiDoc;

pub fn router() -> Router<Arc<ServiceState>> {
    Router::new().nest("/v3", v3::router())
}
