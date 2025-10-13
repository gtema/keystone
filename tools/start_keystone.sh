#!/usr/bin/env bash
set -e

keystone-manage db_sync

keystone-manage fernet_setup --keystone-user root --keystone-group root

keystone-manage bootstrap --bootstrap-user admin --bootstrap-password password --bootstrap-public-url http://localhost:5001 --bootstrap-internal-url http://localhost:8080 --bootstrap-region-id dev

exec uwsgi --module "keystone.server.wsgi:initialize_public_application()" --http-socket :5001 -b 65535 --http-keepalive --so-keepalive --logformat "Request %(uri):%(method) returned %(status) in %(msecs)ms"
