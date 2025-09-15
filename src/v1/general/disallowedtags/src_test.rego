package k8sdisallowedtags

import rego.v1

test_input_allowed_container if {
	inp := {"review": input_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_allowed_dual_container if {
	inp := {"review": input_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_denied_container_emtpy if {
	inp := {"review": input_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_container_latest if {
	inp := {"review": input_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_container_testing if {
	inp := {"review": input_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_dual_container_empty_tag if {
	inp := {"review": input_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_denied_dual_container_2tags if {
	inp := {"review": input_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_denied_mixed_container_empty if {
	inp := {"review": input_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_mixed_container_latest if {
	inp := {"review": input_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

# init containers
test_init_container_input_allowed_container if {
	inp := {"review": input_init_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_allowed_dual_container if {
	inp := {"review": input_init_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_denied_container_emtpy if {
	inp := {"review": input_init_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_denied_container_latest if {
	inp := {"review": input_init_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_denied_container_testing if {
	inp := {"review": input_init_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_denied_dual_container_empty_tag if {
	inp := {"review": input_init_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_denied_dual_container_2tags if {
	inp := {"review": input_init_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_denied_mixed_container_empty if {
	inp := {"review": input_init_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_denied_mixed_container_latest if {
	inp := {"review": input_init_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_denied_mixed_container_with_some_exempt_image if {
	inp := {"review": input_init_review(array.concat(input_container_exempt, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_denied_dual_container_with_all_exempt_image if {
	inp := {"review": input_init_review(array.concat(input_container_exempt, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest", "exempt:testing"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_allowed_dual_container_with_exempt_image if {
	inp := {"review": input_init_review(input_container_exempt), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest", "exempt:testing"]}}
	results := violation with input as inp
	count(results) == 0
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
	"image": "nginx:1.0.0",
}]

input_container_denied_empty := [{
	"name": "nginx",
	"image": "nginx",
}]

input_container_denied_latest := [{
	"name": "nginx",
	"image": "nginx:latest",
}]

input_container_denied_testing := [{
	"name": "other",
	"image": "other:testing",
}]

input_container_dual_allowed := [
	{
		"name": "nginx",
		"image": "nginx:1.0.0",
	},
	{
		"name": "other",
		"image": "other:2.0.0",
	},
]

input_container_exempt := [
	{
		"name": "exempt",
		"image": "exempt:latest",
	},
	{
		"name": "exempt",
		"image": "exempt:testing",
	},
]
