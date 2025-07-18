package identity.group_show

import data.identity

# Show group.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "fetching group details owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching group details requires `reader`."} if {
	identity.own_domain
	not "reader" in input.credentials.roles
}
