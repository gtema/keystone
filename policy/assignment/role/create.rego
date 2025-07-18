package identity.role_create

import data.identity

# Create role.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating role for other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating global role for other domain requires `admin` role."} if {
	identity.no_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating role requires `manager` role."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}
