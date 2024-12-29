use axum::{
    Json, Router,
    extract::{Query, State},
    routing,
};
use std::sync::Arc;

use utoipa::{OpenApi, ToSchema};

use crate::identity::types as identity_types;
use crate::keystone::ServiceState;
use types::{UserListParameters, Users};

mod types;

#[derive(OpenApi)]
#[openapi(
    tags(
        (name="users", description="users api")
    ),
    paths(list)
)]
pub(super) struct UserApi;

pub(super) fn router() -> Router<Arc<ServiceState>> {
    Router::new().route("/", routing::get(list))
}

#[utoipa::path(
    get,
    path = "",
    params(UserListParameters),
    description = "List users op descr",
    responses(
        (status = OK, description = "List of users", body = Users)
    ),
    tag="users"
)]
async fn list(
    Query(query): Query<UserListParameters>,
    State(state): State<Arc<ServiceState>>,
) -> Json<Users> {
    println!("hey");
    let users = state
        .identity
        .list_users(&state.db, &identity_types::UserListParameters {})
        .await;
    let response = Users::from(users);
    Json(response)
}
