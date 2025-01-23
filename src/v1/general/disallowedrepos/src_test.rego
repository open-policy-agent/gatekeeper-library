package k8sdisallowedrepos

import rego.v1

test_input_allowed_container if {
	inp := {"review": input_review(input_container_allowed), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_allowed_container_x2 if {
	inp := {"review": input_review(input_container_allowed), "parameters": {"repos": ["other", "disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_allowed_dual_container if {
	inp := {"review": input_review(input_container_dual_allowed), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_denied_container if {
	inp := {"review": input_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_container_x2 if {
	inp := {"review": input_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_dual_container if {
	inp := {"review": input_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_denied_mixed_container if {
	inp := {"review": input_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 1
}

# init containers
test_input_allowed_initcontainer if {
	inp := {"review": input_init_review(input_container_allowed), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_allowed_initcontainer_x2 if {
	inp := {"review": input_init_review(input_container_allowed), "parameters": {"repos": ["other", "disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_allowed_dual_initcontainer if {
	inp := {"review": input_init_review(input_container_dual_allowed), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_denied_initcontainer if {
	inp := {"review": input_init_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_initcontainer_x2 if {
	inp := {"review": input_init_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_dual_initcontainer if {
	inp := {"review": input_init_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_denied_mixed_initcontainer if {
	inp := {"review": input_init_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
	results := violation with input as inp
	count(results) == 1
}

input_review(containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": containers},
}}

input_init_review(containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"initContainers": containers},
}}

input_container_allowed := [{
	"name": "nginx",
	"image": "allowed/nginx",
}]

input_container_denied := [{
	"name": "nginx",
	"image": "disallowed/nginx",
}]

input_container_dual_allowed := [
	{
		"name": "nginx",
		"image": "allowed/nginx",
	},
	{
		"name": "other",
		"image": "allowed/other",
	},
]

input_container_dual_denied := [
	{
		"name": "nginx",
		"image": "disallowed/nginx",
	},
	{
		"name": "other",
		"image": "disallowed/other",
	},
]
