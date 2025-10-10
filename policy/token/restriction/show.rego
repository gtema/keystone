package identity.token_restriction_show

import data.identity

# Create mapping.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "showing token restrictions requires `admin` role."} if {
	#identity.foreign_mapping
	not "admin" in input.credentials.roles
}

#violation contains {"field": "role", "msg": "creating global mapping requires `admin` role."} if {
#	identity.global_mapping
#	not "admin" in input.credentials.roles
#}
#
#violation contains {"field": "role", "msg": "creating mapping requires `manager` role."} if {
#	identity.own_mapping
#	not "member" in input.credentials.roles
#}
