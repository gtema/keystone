package identity.user_delete

import data.identity

# Show user.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_domain
	"manager" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the user owned by the other domain requires `admin` role."} if {
	identity.foreign_domain
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the user requires `manager` role."} if {
	identity.own_domain
	not "manager" in input.credentials.roles
}
