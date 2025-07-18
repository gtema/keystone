package identity.user_create

import data.identity

# Create user.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating user for other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating user requires `manager` role."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}
