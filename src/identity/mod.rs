use crate::config::Config;
use sea_orm::DatabaseConnection;

pub mod backends;
pub mod types;

use backends::keystone::KeystoneDriver;
use types::IdentityBackend;
use types::User;

pub struct IdentitySrv {
    //config: Config,
    backend_driver: Box<dyn IdentityBackend>,
}

impl IdentitySrv {
    pub fn new(config: &Config) -> Self {
        let driver = match &config.identity {
            Some(identity_config) => match &identity_config.driver {
                Some(val) => match val.as_str() {
                    "keystone" => KeystoneDriver {},
                    _ => KeystoneDriver {},
                },
                _ => KeystoneDriver {},
            },
            _ => KeystoneDriver {},
        };
        Self {
            backend_driver: Box::new(driver),
        }
    }

    pub async fn list_users(
        &self,
        db: &DatabaseConnection,
        params: &types::UserListParameters,
        //   _resource_srv: &ResourceSrv,
    ) -> Vec<User> {
        self.backend_driver.list(db, params).await
    }
}
