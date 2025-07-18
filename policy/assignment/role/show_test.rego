package test_role_show

import data.identity.role_show

test_allowed if {
	role_show.allow with input as {"credentials": {"roles": ["admin"]}}
	role_show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
}

test_forbidden if {
	not role_show.allow with input as {"credentials": {"roles": []}}
	not role_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not role_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
	not role_show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
