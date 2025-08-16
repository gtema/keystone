#!/usr/bin/bash -e

keystone-manage db_sync

keystone-manage fernet_setup --keystone-user root --keystone-group root

keystone-manage bootstrap --bootstrap-user admin --bootstrap-password password --bootstrap-public-url http://localhost:15001 --bootstrap-internal-url http://localhost:18080

uwsgi --http-socket :5000 --module 'keystone.server.wsgi:initialize_public_application()' -b 65535
