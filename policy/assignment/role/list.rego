package identity.role_list

import data.identity

# List roles.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

allow if {
	identity.no_domain
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing roles owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing domain roles requires `manager` role."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing roles requires `admin` role."} if {
	identity.no_domain
	not "admin" in input.credentials.roles
}
