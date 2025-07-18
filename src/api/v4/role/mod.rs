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

use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

use crate::api::v3::role::openapi_router as v3_openapi_router;

pub(crate) static DESCRIPTION: &str = r#"Roles management API.

OpenStack services typically determine whether a user’s API request should be allowed using Role
Based Access Control (RBAC). For OpenStack this means the service compares the roles that user has
on the project (as indicated by the roles in the token), against the roles required for the API in
question (as defined in the service’s policy file). A user obtains roles on a project by having
these assigned to them via the Identity service API.

Roles must initially be created as entities via the Identity services API and, once created, can
then be assigned. You can assign roles to a user or group on a project, including projects owned by
other domains. You can also assign roles to a user or group on a domain, although this is only
currently relevant for using a domain scoped token to execute domain-level Identity service API
requests.

The creation, checking and deletion of role assignments is done with each of the attributes being
specified in the URL. For example to assign a role to a user on a project:

```PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}```

You can also list roles assigned to the system, or to a specified domain, project, or user using
this form of API, however a more generalized API for list assignments is provided where query
parameters are used to filter the set of assignments returned in the collection. For example:

    List role assignments for the specified user:

    GET /role_assignments?user.id={user_id}

    List role assignments for the specified project:

    GET /role_assignments?scope.project.id={project_id}

    List system role assignments for a specific user:

    GET /role_assignments?scope.system=all?user.id={user_id}

    List system role assignments for all users and groups:

    GET /role_assignments?scope.system=all

Since Identity API v3.10, you can grant role assignments to users and groups on an entity called
the system. The role assignment API also supports listing and filtering role assignments on the
system.

Since Identity API v3.6, you can also list all role assignments within a tree of projects, for
example the following would list all role assignments for a specified project and its sub-projects:

GET /role_assignments?scope.project.id={project_id}&include_subtree=true

If you specify include_subtree=true, you must also specify the scope.project.id. Otherwise, this
call returns the Bad Request (400) response code.

Each role assignment entity in the collection contains a link to the assignment that created the
entity.

As mentioned earlier, role assignments can be made to a user or a group on a particular project,
domain, or the entire system. A user who is a member of a group that has a role assignment, will
also be treated as having that role assignment by virtue of their group membership. The effective
role assignments of a user (on a given project or domain) therefore consists of any direct
assignments they have, plus any they gain by virtue of membership of groups that also have
assignments on the given project or domain. This set of effective role assignments is what is
placed in the token for reference by services wishing to check policy. You can list the effective
role assignments using the effective query parameter at the user, project, and domain level:

    Determine what a user can actually do:

    GET /role_assignments?user.id={user_id}&effective

    Get the equivalent set of role assignments that are included in a project-scoped token
    response:

    GET /role_assignments?user.id={user_id}&scope.project.id={project_id}&effective

When listing in effective mode, since the group assignments have been effectively expanded out into
assignments for each user, the group role assignment entities themselves are not returned in the
collection. However, in the response, the links entity section for each assignment gained by virtue
of group membership will contain a URL that enables access to the membership of the group.

By default only the IDs of entities are returned in collections from the role_assignment API calls.
The names of entities may also be returned, in addition to the IDs, by using the include_names
query parameter on any of these calls, for example:

    List role assignments including names:

    GET /role_assignments?include_names


"#;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    v3_openapi_router()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::api::v3::role::types::{
        Role as ApiRole, //GroupCreate as ApiGroupCreate, GroupCreateRequest,
        RoleList,
        RoleResponse,
    };
    use crate::assignment::{
        MockAssignmentProvider,
        types::{Role, RoleListParameters},
    };
    use crate::config::Config;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, MockPolicyFactory, PolicyEvaluationResult};
    use crate::provider::Provider;
    use crate::tests::api::get_mocked_state_unauthed;
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    fn get_mocked_state(assignment_mock: MockAssignmentProvider) -> ServiceState {
        let mut token_mock = MockTokenProvider::default();
        token_mock.expect_validate_token().returning(|_, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }))
        });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .assignment(assignment_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let mut policy_factory_mock = MockPolicyFactory::default();
        policy_factory_mock.expect_instantiate().returning(|| {
            let mut policy_mock = MockPolicy::default();
            policy_mock
                .expect_enforce()
                .returning(|_, _, _, _| Ok(PolicyEvaluationResult::allowed()));
            Ok(policy_mock)
        });
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                policy_factory_mock,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_: &DatabaseConnection, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![Role {
                    id: "1".into(),
                    name: "2".into(),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![ApiRole {
                id: "1".into(),
                name: "2".into(),
                // for some reason when deserializing missing value appears still as an empty
                // object
                extra: Some(json!({})),
                ..Default::default()
            }],
            res.roles
        );
    }

    #[tokio::test]
    async fn test_list_qp() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_roles()
            .withf(|_: &DatabaseConnection, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some("domain".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain&name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: RoleList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state_unauthed();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_get_role()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        assignment_mock
            .expect_get_role()
            .withf(|_: &DatabaseConnection, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(Role {
                    id: "bar".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(assignment_mock);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiRole {
                id: "bar".into(),
                extra: Some(json!({})),
                ..Default::default()
            },
            res.role,
        );
    }
}
