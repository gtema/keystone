package test_identity_provider_list

import data.identity.identity_provider_list

test_allowed if {
	identity_provider_list.allow with input as {"credentials": {"roles": ["admin"]}}
	identity_provider_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	identity_provider_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
}

test_forbidden if {
	not identity_provider_list.allow with input as {"credentials": {"roles": []}}
	not identity_provider_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not identity_provider_list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
