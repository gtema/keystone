package identity.user_show

import data.identity

# Show user.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "fetching user details owned by other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching user details requires `reader`."} if {
	identity.own_domain
	not "reader" in input.credentials.roles
}
