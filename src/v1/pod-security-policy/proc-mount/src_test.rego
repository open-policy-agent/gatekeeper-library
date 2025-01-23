package k8spspprocmount

import rego.v1

test_input_container_not_proc_mount_allowed if {
	inp := {"review": input_review, "parameters": input_parameters_default}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_proc_mount_not_allowed if {
	inp := {"review": input_review_unmasked, "parameters": input_parameters_default}
	results := violation with input as inp
	count(results) == 1
}

test_input_container_proc_mount_not_allowed_null_param if {
	inp := {"review": input_review_unmasked, "parameters": null}
	results := violation with input as inp
	count(results) == 1
}

test_input_container_proc_mount_not_allowed_missing_param if {
	inp := {"review": input_review_unmasked}
	results := violation with input as inp
	count(results) == 1
}

test_input_container_many_not_proc_mount_allowed if {
	inp := {"review": input_review_many, "parameters": input_parameters_default}
	results := violation with input as inp
	print(results)
	count(results) == 0
}

test_input_container_many_mixed_proc_mount_not_allowed if {
	inp := {"review": input_review_many_mixed, "parameters": input_parameters_default}
	results := violation with input as inp
	count(results) == 1
}

test_input_container_many_mixed_proc_mount_not_allowed_two if {
	inp := {"review": input_review_many_mixed_two, "parameters": input_parameters_default}
	results := violation with input as inp
	count(results) == 2
}

test_input_container_many_mixed_proc_mount_not_allowed_two_but_exempt if {
	inp := {"review": input_review_many_mixed_two, "parameters": input_parameters_exempt}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_proc_mount_case_insensitive if {
	inp := {"review": input_review, "parameters": input_parameters_default_lower}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_proc_mount_case_invalid_procMount if {
	inp := {"review": input_review, "parameters": input_parameters_invalid_procMount}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_not_proc_mount_unmasked if {
	inp := {"review": input_review, "parameters": input_parameters_unmasked}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_proc_mount_unmasked if {
	inp := {"review": input_review_unmasked, "parameters": input_parameters_unmasked}
	results := violation with input as inp
	count(results) == 0
}

test_input_container_many_mixed_proc_mount_allowed_two if {
	inp := {"review": input_review_many_mixed_two, "parameters": input_parameters_unmasked}
	results := violation with input as inp
	count(results) == 0
}

test_update if {
	inp := {"review": object.union(input_review_unmasked, {"operation": "UPDATE"}), "parameters": input_parameters_default}
	results := violation with input as inp
	count(results) == 0
}

input_review := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": input_containers_one},
}}

input_review_unmasked := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": input_containers_one_unmasked},
}}

input_review_many := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {
		"containers": input_containers_many,
		"initContainers": input_containers_one,
	},
}}

input_review_many_mixed := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {
		"containers": input_containers_many,
		"initContainers": input_containers_one_unmasked,
	},
}}

input_review_many_mixed_two := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {
		"containers": input_containers_many_mixed,
		"initContainers": input_containers_one_unmasked,
	},
}}

input_containers_one := [{
	"name": "nginx",
	"image": "nginx",
	"securityContext": {"procMount": "Default"},
}]

input_containers_one_unmasked := [{
	"name": "nginx",
	"image": "nginx",
	"securityContext": {"procMount": "Unmasked"},
}]

input_containers_many := [
	{
		"name": "nginx",
		"image": "nginx",
		"securityContext": {"procMount": "Default"},
	},
	{
		"name": "nginx1",
		"image": "nginx",
	},
	{
		"name": "nginx2",
		"image": "nginx",
		"securityContext": {"runAsUser": "1000"},
	},
]

input_containers_many_mixed := [
	{
		"name": "nginx",
		"image": "nginx",
		"securityContext": {"procMount": "Default"},
	},
	{
		"name": "nginx1",
		"image": "nginx",
		"securityContext": {"procMount": "Unmasked"},
	},
]

input_parameters_default := {"procMount": "Default"}

input_parameters_default_lower := {"procMount": "default"}

input_parameters_unmasked := {"procMount": "Unmasked"}

input_parameters_exempt := {
	"exemptImages": ["nginx"],
	"procMount": "Default",
}

input_parameters_invalid_procMount := {"procMount": "invalid"}
