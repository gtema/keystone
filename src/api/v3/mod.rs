use axum::Router;
use std::sync::Arc;
use utoipa::OpenApi;

use crate::keystone::ServiceState;

pub mod user;

#[derive(OpenApi)]
#[openapi(
    info(description = "test"),
    nest(
        (path = "/users", api = user::UserApi)
    )
)]
pub(super) struct V3Api;

pub(super) fn router() -> Router<Arc<ServiceState>> {
    Router::new().nest("/users", user::router())
}
