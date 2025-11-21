package identity.role_assignment.check

import data.identity

# List role assignments

default allow := false

allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}

allow if {
	identity.own_domain
	"reader" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"system" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing role assignments for other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing role assignments for the own domain requires `reader` role."} if {
	identity.own_idp
	not "reader" in input.credentials.roles
}
