package identity.role_show

import data.identity

# Show role.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "fetching role details owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching role details requires `reader`."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching role details requires `admin`."} if {
	identity.no_domain
	not "admin" in input.credentials.roles
}
