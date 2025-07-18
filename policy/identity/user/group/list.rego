package identity.user_group_list

import data.identity

# List user groups.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing user groups owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing user groups requires `reader` role."} if {
	identity.own_domain
	not "reader" in input.credentials.roles
}
