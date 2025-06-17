# OpenStack Keystone in Rust

What happens if OpenStack Keystone would be rewritten in Rust? Is it possible?
How complex is it? Which improvements are possible?

This project exists to answer this questions.

Primary target of the project is to implement a Rust library implementing
Keystone functionality to be able to split a Keystone monolith into smaller
pieces (similar to the microservices). Once this is done, adding an API is
becoming also pretty simple.

It targets deploying Python and Rust implementation in parallel and do request
routing on the web server level to get the speed and security of Rust
implementation while keeping functions not implemented (yet) being served by the
original Keystone. This approach also makes it possible to deploy Rust
implementation in parallel to a much older version of Keystone giving
possibility for the operators to enable new features while still using older
version of Keystone (whatever the reason for that is).


## Compatibility

Highest priority is to ensure that this implementation is compatible with the
original python Keystone: authentication issued by Rust implementation is
accepted by the Python Keystone and vice versa. At the same time it is
expected, that the new implementation may implement new features not supported
by the Python implementation. In this case, it is still expected that such
features do not break authentication flows. It must be possible to deploy
Python and Rust implementation in parallel and do request routing on the web
server level.

## Database

Adding new features most certanly require having database changes. It is not
expected that such changes interfere with the Python implementation to ensure
it is working correctly.

## API

Also here it is expected that new API resources are going to be added. As above
it is not expected that such changes interfere with the Python implementation
to ensure it is still working correctly and existing clients will not break.
