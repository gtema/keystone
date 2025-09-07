package identity

token_subject if {
	input.credentials.user_id == input.target.token.user_id
}

global_idp if {
	not input.target.domain_id
}

global_idp if {
	input.target.domain_id == null
}

own_idp if {
	input.target.domain_id != null
	input.target.domain_id == input.credentials.domain_id
}

foreign_idp if {
	input.target.domain_id != null
	input.target.domain_id != input.credentials.domain_id
}

global_mapping if {
	not input.target.domain_id
}

global_mapping if {
	input.target.domain_id == null
}

own_mapping if {
	input.target.domain_id != null
	input.target.domain_id == input.credentials.domain_id
}

foreign_mapping if {
	input.target.domain_id != null
	input.target.domain_id != input.credentials.domain_id
}
