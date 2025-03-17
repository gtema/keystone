pub use sea_orm_migration::prelude::*;

mod m20250301_000001_passkey;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20250301_000001_passkey::Migration)]
    }
}
