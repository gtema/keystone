package test_token_restriction_show

import data.identity.token_restriction_show

test_allowed if {
	token_restriction_show.allow with input as {"credentials": {"roles": ["admin"]}}
	#token_restriction_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	#token_restriction_show.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not token_restriction_show.allow with input as {"credentials": {"roles": []}}
	not token_restriction_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not token_restriction_show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
