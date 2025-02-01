# OpenStack Keystone in Rust

Attempt to provide Rust library for OpenStack Keystone functionality by
implementing database access in the same way as Keystone does. When the concept
proves usability this might become a base for reimplementing Keystone in Rust.

## Config

Keystone config is being read and the main goal is to have possibility to
simply reuse Keystone config with no changes.

## Api + OpenAPI

OpenAPI are being built directly from the code to guarantee the documentation
matches the implementation.

## Database

Sea-ORM is being used to access database. PostgreSQL and MySQL are supported.
