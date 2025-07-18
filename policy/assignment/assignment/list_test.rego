package test_role_assignment_list

import data.identity.role_assignment_list

test_allowed if {
	role_assignment_list.allow with input as {"credentials": {"roles": ["admin"]}}
	role_assignment_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
}

test_forbidden if {
	not role_assignment_list.allow with input as {"credentials": {"roles": []}}
	not role_assignment_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not role_assignment_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not role_assignment_list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
