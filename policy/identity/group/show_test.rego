package test_group_show

import data.identity.group_show

test_allowed if {
	group_show.allow with input as {"credentials": {"roles": ["admin"]}}
	group_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
}

test_forbidden if {
	not group_show.allow with input as {"credentials": {"roles": []}}
	not group_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not group_show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
