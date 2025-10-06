# Installation

The easiest way to get started with the keystone-ng is using the container
image. It is also possible to use the compiled version. It can be either
compiled locally or downloaded from the project artifacts.

## Using pre-compiled binaries

As of the moment of writing there were no releases. Due to that there are no
pre-compiled binaries available yet. Every release of the project would include
the pre-compiled binaries for a variety of platforms.

## Compiling

In order to compile the keystone-ng it is necessary to have the rust compiler
available. It may be installed from the system packages or using the
`rustup.rs`

```console
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Afterwards in the root of the project source tree following command may be
executed to invoke the `cargo`

```console

cargo build --release

```

It produces 2 binaries:

- target/release/keystone (the api server)

- target/release/keystone-db (the database management tool)

Currently keystone depends on the openssl (through one of the dependencies).
Depending on the environment it may be a statically linked or dynamically.
There are signals that that may be not necessary anymore once all dependencies
transition to the use of rustls.

## Using containers

It is possible to run Keystone-ng inside containers. A sample Dockerfile is
present in the project source tree to build container image with the Keystone
and the `keystone-db` utility. When no ready image is available it can be build
like that:

```console

docker build . -t keystone:rust

```

Since keystone itself communicates with the database and OpenPolicyAgent those
must be provided separately. `docker-compose.yaml` demonstrates how this can be
done.

```console

docker run -v /etc/keystone/:/etc/keystone -p 8080:8080 ghcr.io/gtema/keystone:main -v /etc/keystone/keystone.conf
```

## Database migrations

Rust Keystone is using different ORM and implements migration that co-exist
together with alembic migrations of the python Keystone. It also ONLY manages
the database schema additions and does NOT include the original database
schema. Therefore it is necessary to apply both migrations.

```console
keystone-db -u <DB_URL>
```

It is important to also understand that the DB_URL may differ between python
and rust due to the optional presence of the preferred database driver in the
url. keystone-ng will ignore the the driver in the application itself, but the
migration may require user to manually remove it since it is being processed by
the ORM itself and not by the keystone-ng code.

## OpenPolicyAgent

keystone-ng relies on the OPA for policy enforcement. Default policies are
provided with the project and can be passed directly to the OPA process or
compiled into the bundle.

```console

opa run -s policies

```

**NOTE:** by default OPA process listens on the localhost only what lead to
unavailability to expose it between containers. Please use `-a 0.0.0.0:8181` to

start listening on all interfaces.
