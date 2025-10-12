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
configured amount (defaults to count of the cpu cores), keeps the load for the
configured amount of time while measuring the response latency and the throughput (RPS).

For every PR load test suite is being executed. It is absolutely clear that the Rust implementation currently misses certain things original Keystone doe, but the gap is being closed over the time. However test shows
difference of factor **10-100** which is already remarkable. New tests will appear to have a more thorough coverage of the exposed API.

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
