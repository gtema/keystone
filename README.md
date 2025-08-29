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

## Load test

A very brief load test is implemented in `loadtest` using `Goose` framework. It
generates test load by first incrementally increasing requests up to the
configure amount (defaults to amount of cpu cores), keeps the load for the
configured amount of time measuring response latency.

First brief results comparing python implementation (running under uwsgi) vs
Rust implementation are present in the `loadtest/report_py.html` and
`loadtest/report_rust.html`. It is absolutely clear that Rust implementation
currently misses certain things original Keystone does (token validation is at
the moment fake, policy evaluation is also missing, etc). In addition to that
more reasonable test environment (comparable amount of python workers, etc,
debug/release build) need to be established. However current test shows
difference of factor **100** which is not going to be easy to beat.

## Trying

Trying Keystone (assuming you have the Rust build environment or you are in the
possession of the binary is as easy as `keystone -c etc/keystone.conf -vv`

Alternatively you can try it with `docker compose -f docker-compose.yaml up`.

## Documentation

Comprehensive (as much as it can be at the current stage) is available
[here](https://gtema.github.io/keystone).

## Talks

Detailed introduction of the project was given as
[ALASCA tech talk](https://www.youtube.com/watch?v=0Hx4Q22ZNFU).
