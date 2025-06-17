# Installation

TODO:

- Prepare the binary (download from GH releases, build yourself, use the
  container image, ...)

- Perform the DB migration `keystone-db up`

- Start the binary as `keystone -c <PATH_TO_THE_KEYSTONE_CONFIG>`


## Database migrations

Rust Keystone is using different ORM and implements migration that co-exist
together with alembic migrations of the python Keystone. It also ONLY manages
the database schema additions and does NOT include the original database
schema. Therefore it is necessary to apply both migrations.
