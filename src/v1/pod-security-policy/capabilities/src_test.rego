package capabilities

import rego.v1

test_input_all_allowed if {
	inp := {"review": input_review([cadd(["one", "two"])]), "parameters": {"allowedCapabilities": ["*"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_all_allowed_container_x2 if {
	inp := {"review": input_review([cadd(["one", "two"]), cadd(["three"])]), "parameters": {"allowedCapabilities": ["*"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_one_allowed if {
	inp := {"review": input_review([cadd(["one"])]), "parameters": {"allowedCapabilities": ["one"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_one_allowed_container_x2 if {
	inp := {"review": input_review([cadd(["one"]), cadd(["one"])]), "parameters": {"allowedCapabilities": ["one"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_two_allowed_container_x2 if {
	inp := {"review": input_review([cadd(["one"]), cadd(["two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_two_allowed_two_used_container_x2 if {
	inp := {"review": input_review([cadd(["one", "two"]), cadd(["one", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_none_allowed if {
	inp := {"review": input_review([cadd(["one"])]), "parameters": {"allowedCapabilities": []}}
	results := violation with input as inp
	count(results) == 1
}

test_input_none_allowed_undefined if {
	inp := {"review": input_review([cadd(["one"])]), "parameters": {}}
	results := violation with input as inp
	count(results) == 1
}

test_input_none_allowed_undefined_x2_x2 if {
	inp := {"review": input_review([cadd(["one", "two"]), cadd(["three", "two"])]), "parameters": {}}
	results := violation with input as inp
	trace(sprintf("results are: %v", [results]))
	count(results) == 2
}

test_input_disallowed_x1 if {
	inp := {"review": input_review([cadd(["three"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_disallowed_x2_just_one if {
	inp := {"review": input_review([cadd(["one"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_disallowed_x2 if {
	inp := {"review": input_review([cadd(["three"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_disallowed_x2_but_exempt if {
	inp := {"review": input_review([cadd(["three"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"], "exemptImages": ["nginx"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_empty_drop if {
	inp := {"review": input_review([cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": []}}
	results := violation with input as inp
	count(results) == 0
}

test_input_all_dropped if {
	inp := {"review": input_review([cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_extra_dropped if {
	inp := {"review": input_review([cdrop(["one", "two", "three"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_all_dropped_x2 if {
	inp := {"review": input_review([cdrop(["one", "two"]), cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_missing_drop if {
	inp := {"review": input_review([cdrop(["two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_one_missing_drop_x2 if {
	inp := {"review": input_review([cdrop(["one"]), cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_missing_drop_x2 if {
	inp := {"review": input_review([cdrop(["one"]), cdrop(["two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_drop_undefined_x2 if {
	inp := {"review": input_review([cadd([]), cadd([])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_drop_undefined_x2_but_exempt if {
	inp := {"review": input_review([cadd([]), cadd([])]), "parameters": {"requiredDropCapabilities": ["one", "two"], "exemptImages": ["nginx"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_drop_literal_all if {
	inp := {"review": input_review([cdrop(["ALL"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_drop_literal_all_lower if {
	inp := {"review": input_review([cdrop(["all"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_drop_literal_all_with_all_param if {
	inp := {"review": input_review([cdrop(["ALL"])]), "parameters": {"requiredDropCapabilities": ["one", "ALL"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_drop_literal_all_x2 if {
	inp := {"review": input_review([cdrop(["ALL", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_update if {
	inp := {"review": object.union(input_review([cadd(["one"])]), {"operation": "UPDATE"}), "parameters": {"allowedCapabilities": []}}
	results := violation with input as inp
	count(results) == 0
}

# init containers
test_init_container_input_all_allowed if {
	inp := {"review": input_init_review([cadd(["one", "two"])]), "parameters": {"allowedCapabilities": ["*"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_all_allowed_container_x2 if {
	inp := {"review": input_init_review([cadd(["one", "two"]), cadd(["three"])]), "parameters": {"allowedCapabilities": ["*"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_one_allowed if {
	inp := {"review": input_init_review([cadd(["one"])]), "parameters": {"allowedCapabilities": ["one"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_one_allowed_container_x2 if {
	inp := {"review": input_init_review([cadd(["one"]), cadd(["one"])]), "parameters": {"allowedCapabilities": ["one"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_two_allowed_container_x2 if {
	inp := {"review": input_init_review([cadd(["one"]), cadd(["two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_two_allowed_two_used_container_x2 if {
	inp := {"review": input_init_review([cadd(["one", "two"]), cadd(["one", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_none_allowed if {
	inp := {"review": input_init_review([cadd(["one"])]), "parameters": {"allowedCapabilities": []}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_none_allowed_undefined if {
	inp := {"review": input_init_review([cadd(["one"])]), "parameters": {}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_none_allowed_undefined_x2_x2 if {
	inp := {"review": input_init_review([cadd(["one", "two"]), cadd(["three", "two"])]), "parameters": {}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_disallowed_x1 if {
	inp := {"review": input_init_review([cadd(["three"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_disallowed_x2_just_one if {
	inp := {"review": input_init_review([cadd(["one"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_disallowed_x2 if {
	inp := {"review": input_init_review([cadd(["three"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_disallowed_x2_but_exempt if {
	inp := {"review": input_init_review([cadd(["three"]), cadd(["three", "two"])]), "parameters": {"allowedCapabilities": ["one", "two"], "exemptImages": ["nginx"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_empty_drop if {
	inp := {"review": input_init_review([cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": []}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_all_dropped if {
	inp := {"review": input_init_review([cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_extra_dropped if {
	inp := {"review": input_init_review([cdrop(["one", "two", "three"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_all_dropped_x2 if {
	inp := {"review": input_init_review([cdrop(["one", "two"]), cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_missing_drop if {
	inp := {"review": input_init_review([cdrop(["two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_one_missing_drop_x2 if {
	inp := {"review": input_init_review([cdrop(["one"]), cdrop(["one", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_missing_drop_x2 if {
	inp := {"review": input_init_review([cdrop(["one"]), cdrop(["two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_drop_undefined_x2 if {
	inp := {"review": input_init_review([cadd([]), cadd([])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 2
}

test_init_container_input_drop_undefined_x2_but_exempt if {
	inp := {"review": input_init_review([cadd([]), cadd([])]), "parameters": {"requiredDropCapabilities": ["one", "two"], "exemptImages": ["nginx"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_drop_literal_all if {
	inp := {"review": input_init_review([cdrop(["ALL"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_drop_literal_all_lower if {
	inp := {"review": input_init_review([cdrop(["all"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_drop_literal_all_with_all_param if {
	inp := {"review": input_init_review([cdrop(["ALL"])]), "parameters": {"requiredDropCapabilities": ["one", "ALL"]}}
	results := violation with input as inp
	count(results) == 0
}

test_init_container_input_drop_literal_with_all_param if {
	inp := {"review": input_init_review([cdrop(["one"])]), "parameters": {"requiredDropCapabilities": ["one", "ALL"]}}
	results := violation with input as inp
	count(results) == 1
}

test_init_container_input_drop_literal_all_x2 if {
	inp := {"review": input_init_review([cdrop(["ALL", "two"])]), "parameters": {"requiredDropCapabilities": ["one", "two"]}}
	results := violation with input as inp
	count(results) == 0
}

input_review(containers) := output if {
	cs := [o |
		some i, c in containers
		o := inject_name(i, c)
	]
	output = {"object": {
		"metadata": {"name": "nginx"},
		"spec": {"containers": cs},
	}}
}

input_init_review(containers) := output if {
	cs := [o |
		some i, c in containers
		o := inject_name(i, c)
	]
	output = {"object": {
		"metadata": {"name": "nginx"},
		"spec": {"initContainers": cs},
	}}
}

cdrop(drop) := {
	"image": "nginx",
	"securityContext": {"capabilities": {"drop": drop}},
}

cadd(add) := {
	"image": "nginx",
	"securityContext": {"capabilities": {"add": add}},
}

inject_name(name, obj) := out if {
	all_keys := object.keys(obj) | {"name"}
	out := {k: v |
		some k in all_keys
		v := get_default(obj, k, name)
	}
}
