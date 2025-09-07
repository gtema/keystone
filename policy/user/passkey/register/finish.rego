package identity.user.passkey.register.finish

import data.identity

# Finish registering a passkey for the user

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"manager" in input.credentials.roles
	input.credentials.domain_id == input.target.domain_id
}

allow if {
	input.credentials.user_id == input.target.id
}
