use sea_orm::DatabaseConnection;
use std::sync::Arc;

use crate::config::Config;
use crate::identity::IdentitySrv;

#[derive(Clone)]
pub struct ServiceState {
    config: Config,
    pub identity: Arc<IdentitySrv>,
    pub db: DatabaseConnection,
    // ...
}
impl ServiceState {
    pub fn new(cfg: Config, db: DatabaseConnection) -> Self {
        let identity = Arc::new(IdentitySrv::new(&cfg));
        Self {
            config: cfg.clone(),
            identity,
            db,
        }
    }
}

//pub struct KeystoneService {
//    config: Config,
//    pub identity: IdentitySrv,
//    pub resource: ResourceSrv,
//    //user_backend: Box<dyn identity::types::UserBackend>,
//}
//
//impl KeystoneService {
//    pub fn new(cfg: &Config) -> Self {
//        let config = cfg.clone();
//        let identity = IdentitySrv::new(&config);
//        let resource = ResourceSrv::new();
//        Self {
//            config,
//            identity,
//            resource, //user_backend: Box::new(identity::backends::keystone::KeystoneDriver {}),
//        }
//    }
//
//    //fn get_identity_service(&mut self) -> &mut IdentitySrv {
//    //    &mut self.identity
//    //}
//}
