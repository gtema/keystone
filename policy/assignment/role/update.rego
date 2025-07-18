package identity.role_update

import data.identity

default allow := false

# Update role.

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "updating role for other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating role requires `admin` role."} if {
	identity.no_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating role requires `manager` role."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}
