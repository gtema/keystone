package test_mapping_list

import data.identity.mapping_list

test_allowed if {
	mapping_list.allow with input as {"credentials": {"roles": ["admin"]}}
	mapping_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	mapping_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
}

test_forbidden if {
	not mapping_list.allow with input as {"credentials": {"roles": []}}
	not mapping_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not mapping_list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
