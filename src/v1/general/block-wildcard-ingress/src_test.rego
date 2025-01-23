package K8sBlockWildcardIngress

import rego.v1

test_input_ingress_allowed_host if {
	inp := {"review": input_review(input_ingress_allowed_host)}
	results := violation with input as inp
	count(results) == 0
}

test_input_ingress_disallowed_wildcard_host if {
	inp := {"review": input_review(input_ingress_disallowed_wildcard_host)}
	results := violation with input as inp
	count(results) == 1
}

test_input_ingress_disallowed_empty_host if {
	inp := {"review": input_review(input_ingress_disallowed_empty_host)}
	results := violation with input as inp
	count(results) == 1
}

test_input_ingress_no_rules if {
	inp := {"review": input_review(input_ingress_no_rules)}
	results := violation with input as inp
	count(results) == 1
}

input_review(rules) := {
	"kind": {"kind": "Ingress"},
	"object": {"spec": {"rules": rules}},
}

input_ingress_allowed_host := [{"host": "foo.bar.com"}]

input_ingress_disallowed_wildcard_host := [
	{"host": "foo.bar.com"},
	{"host": "*.foo.com"},
]

input_ingress_disallowed_empty_host := [{"host": ""}]

input_ingress_no_rules := [{}]
