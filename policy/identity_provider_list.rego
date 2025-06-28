package identity.identity_provider_list

# List identity providers.

default allow := false

allow if {
	count(violation) == 0
}

violation contains {"field": "domain_id", "msg": "only admin user is allowed to list identity providers not owned by the domain in scope."} if {
	not "admin" in input.credentials.roles
	not global_or_local_idp
}

global_idp if {
	not input.target.domain_id
}

local_idp if {
	input.target.domain_id == input.credentials.domain_id
}

global_or_local_idp if {
	global_idp
}

global_or_local_idp if {
	local_idp
}
