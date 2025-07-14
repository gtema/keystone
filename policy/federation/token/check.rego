package identity.check_token

import data.identity

# Update mapping.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
  "all" in input.credentials.system_scope
}

allow if {
  identity.token_subject
}

allow if {
	"service" in input.credentials.roles
}
