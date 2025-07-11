package test_mapping_create

import data.identity.mapping_create

test_allowed if {
	mapping_create.allow with input as {"credentials": {"roles": ["admin"]}}
	mapping_create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	mapping_create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not mapping_create.allow with input as {"credentials": {"roles": []}}
	not mapping_create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	not mapping_create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not mapping_create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
