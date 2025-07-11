package test_identity_provider_delete

import data.identity.identity_provider_delete

test_allowed if {
	identity_provider_delete.allow with input as {"credentials": {"roles": ["admin"]}}
	identity_provider_delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	identity_provider_delete.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not identity_provider_delete.allow with input as {"credentials": {"roles": []}}
	not identity_provider_delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	not identity_provider_delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not identity_provider_delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
