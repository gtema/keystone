package identity.auth.token.show

import data.identity

# Validate the token

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"service" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}

allow if {
	identity.token_subject
}

