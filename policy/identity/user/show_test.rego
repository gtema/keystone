package test_user_show

import data.identity.user_show

test_allowed if {
	user_show.allow with input as {"credentials": {"roles": ["admin"]}}
	user_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
}

test_forbidden if {
	not user_show.allow with input as {"credentials": {"roles": []}}
	not user_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not user_show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
