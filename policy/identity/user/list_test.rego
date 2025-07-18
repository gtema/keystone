package test_user_list

import data.identity.user_list

test_allowed if {
	user_list.allow with input as {"credentials": {"roles": ["admin"]}}
	user_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	user_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
}

test_forbidden if {
	not user_list.allow with input as {"credentials": {"roles": []}}
	not user_list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not user_list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
