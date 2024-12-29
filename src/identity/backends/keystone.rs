use super::super::types::*;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

mod local_user;
mod user;

use local_user::Entity as DbLocalUser;
use user::Entity as DbUser;

pub struct KeystoneDriver {}

#[async_trait]
impl IdentityBackend for KeystoneDriver {
    async fn list(&self, db: &DatabaseConnection, _params: &UserListParameters) -> Vec<User> {
        let db_users: Vec<(user::Model, Option<local_user::Model>)> = DbUser::find()
            .find_also_related(DbLocalUser)
            .all(db)
            .await
            .unwrap();
        println!("data is {:?}", db_users);
        for (a, b) in &db_users {
            println!("data is {:?} {:?}", a, b);
        }
        let dblocal_users: Vec<local_user::Model> = DbLocalUser::find()
            .all(db)
            .await
            .unwrap();
        println!("data is {:?}", dblocal_users);
        db_users
            .into_iter()
            .map(|(x, y)| User {
                id: x.id.clone(),
                domain_id: x.domain_id.clone(),
                name: y.map(|z| z.name),
            })
            .collect()
        //for user in users.iter() {
        //}
        //vec![User { id: "foo".into() }]
    }
}
