package test_mapping_show

import data.identity.mapping_show

test_allowed if {
	mapping_show.allow with input as {"credentials": {"roles": ["admin"]}}
	mapping_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	mapping_show.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not mapping_show.allow with input as {"credentials": {"roles": []}}
	not mapping_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not mapping_show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
