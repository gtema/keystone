package test_role_list

import data.identity.role_list

test_allowed if {
	role_list.allow with input as {"credentials": {"roles": ["admin"]}}
	role_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
}

test_forbidden if {
	not role_list.allow with input as {"credentials": {"roles": []}}
	not role_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not role_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not role_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
