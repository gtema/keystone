package identity.group_list

import data.identity

# List groups.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"reader" in input.credentials.roles
}

allow if {
	identity.no_domain
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing groups owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing domain groups requires `reader` role."} if {
	identity.own_domain
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing groups requires `reader` role."} if {
	identity.no_domain
	not "reader" in input.credentials.roles
}
