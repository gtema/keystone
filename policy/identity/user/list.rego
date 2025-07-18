package identity.user_list

import data.identity

# List users.

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

violation contains {"field": "domain_id", "msg": "listing users owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing domain users requires `reader` role."} if {
	identity.own_domain
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing users requires `reader` role."} if {
	identity.no_domain
	not "reader" in input.credentials.roles
}
