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
//! Create project group role assignment.

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
//use crate::api::v4::federation::types::*;
//use crate::federation::FederationApi;
use crate::api::common::build_enforcement_target;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Assign role to group on project.
///
/// Assigns a role to a group on a project.
#[utoipa::path(
    post,
    path = "/{role_id}",
    operation_id = "/projects/group/role:create",
    responses(
        (status = NO_CONTENT, description = "Success"),
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::v3::project::group::role::create",
    level = "debug",
    skip(state, user_auth, policy)
)]
#[debug_handler]
pub(super) async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Path((project_id, group_id, role_id)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce(
            "identity/role_assignment/create_grant",
            &user_auth,
            build_enforcement_target(
                &state,
                Some(role_id),
                Some(project_id),
                None,
                None,
                Some(group_id),
            )
            .await?,
            None,
        )
        .await?;

    //let res = state
    //    .provider
    //    .get_federation_provider()
    //    .create_mapping(&state, req.into())
    //    .await
    //    .map_err(KeystoneApiError::federation)?;
    Ok((StatusCode::NO_CONTENT).into_response())
}

//#[cfg(test)]
//mod tests {
//    use axum::{
//        body::Body,
//        http::{Request, StatusCode, header},
//    };
//    use http_body_util::BodyExt; // for `collect`
//
//    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
//    use tower_http::trace::TraceLayer;
//    use tracing_test::traced_test;
//
//    use super::{
//        super::{openapi_router, tests::get_mocked_state},
//        *,
//    };
//
//    use crate::federation::{MockFederationProvider, types as provider_types};
//
//    #[tokio::test]
//    #[traced_test]
//    async fn test_create() {
//        let mut federation_mock = MockFederationProvider::default();
//        federation_mock
//            .expect_create_mapping()
//            .withf(|_, req: &provider_types::Mapping| req.name == "name")
//            .returning(|_, _| {
//                Ok(provider_types::Mapping {
//                    id: "bar".into(),
//                    name: "name".into(),
//                    domain_id: Some("did".into()),
//                    ..Default::default()
//                })
//            });
//
//        let state = get_mocked_state(federation_mock, true);
//
//        let mut api = openapi_router()
//            .layer(TraceLayer::new_for_http())
//            .with_state(state.clone());
//
//        let req = MappingCreateRequest {
//            mapping: MappingCreate {
//                name: "name".into(),
//                domain_id: Some("did".into()),
//                ..Default::default()
//            },
//        };
//
//        let response = api
//            .as_service()
//            .oneshot(
//                Request::builder()
//                    .method("POST")
//                    .header(header::CONTENT_TYPE, "application/json")
//                    .uri("/")
//                    .header("x-auth-token", "foo")
//                    .body(Body::from(serde_json::to_string(&req).unwrap()))
//                    .unwrap(),
//            )
//            .await
//            .unwrap();
//
//        assert_eq!(response.status(), StatusCode::CREATED);
//
//        let body = response.into_body().collect().await.unwrap().to_bytes();
//        let res: MappingResponse = serde_json::from_slice(&body).unwrap();
//        assert_eq!(res.mapping.name, req.mapping.name);
//        assert_eq!(res.mapping.domain_id, req.mapping.domain_id);
//    }
//}
