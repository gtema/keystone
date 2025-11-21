package identity.role_assignment.create

import data.identity

# Create role assignment grant.
# TODO: upstream policy is insanely complex. Current policy mostly only cover
# subset.

default allow := false

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"system" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating role assignments for other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}
