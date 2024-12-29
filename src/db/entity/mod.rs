//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

pub mod prelude;

pub mod access_rule;
pub mod access_token;
pub mod alembic_version;
pub mod application_credential;
pub mod application_credential_access_rule;
pub mod application_credential_role;
pub mod assignment;
pub mod config_register;
pub mod consumer;
pub mod credential;
pub mod endpoint;
pub mod endpoint_group;
pub mod expiring_user_group_membership;
pub mod federated_user;
pub mod federation_protocol;
pub mod group;
pub mod id_mapping;
pub mod identity_provider;
pub mod idp_remote_ids;
pub mod implied_role;
pub mod limit;
pub mod local_user;
pub mod mapping;
pub mod nonlocal_user;
pub mod password;
pub mod policy;
pub mod policy_association;
pub mod project;
pub mod project_endpoint;
pub mod project_endpoint_group;
pub mod project_option;
pub mod project_tag;
pub mod region;
pub mod registered_limit;
pub mod request_token;
pub mod revocation_event;
pub mod role;
pub mod role_option;
pub mod sea_orm_active_enums;
pub mod sensitive_config;
pub mod service;
pub mod service_provider;
pub mod system_assignment;
pub mod token;
pub mod trust;
pub mod trust_role;
pub mod user;
pub mod user_group_membership;
pub mod user_option;
pub mod whitelisted_config;
