package test_group_list

import data.identity.group_list

test_allowed if {
	group_list.allow with input as {"credentials": {"roles": ["admin"]}}
	group_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	group_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
}

test_forbidden if {
	not group_list.allow with input as {"credentials": {"roles": []}}
	not group_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not group_list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
