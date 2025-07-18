package identity.role_assignment_list

import data.identity

# List role_assignments.

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

violation contains {"field": "domain_id", "msg": "listing role_assignments owned by other domain requires `admin` role_assignment."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role_assignment", "msg": "listing domain role_assignments requires `manager` role_assignment."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}

violation contains {"field": "role_assignment", "msg": "listing role_assignments requires `admin` role_assignment."} if {
	identity.no_domain
	not "admin" in input.credentials.roles
}
