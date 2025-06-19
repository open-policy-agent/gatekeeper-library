package k8srequiredresources

import rego.v1

# "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}
test_without_resources_violations if {
	inp := {"review": review([ctr_without_resources("test")]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_requests_cpu_violations if {
	inp := {"review": review([ctr_requests_cpu("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_requests_memory_violations if {
	inp := {"review": review([ctr_requests_memory("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_requests_violations if {
	inp := {"review": review([ctr_requests("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_limits_cpu_violations if {
	inp := {"review": review([ctr_limits_cpu("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_limits_memory_violations if {
	inp := {"review": review([ctr_limits_memory("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_limits_violations if {
	inp := {"review": review([ctr_limits("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_with_resources_no_violations if {
	inp := {"review": review([ctr_with_resources("test", 1)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

# "parameters": {"limits": ["memory"], "requests": ["cpu"]}
test_without_resources_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_without_resources("test")]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_requests_cpu_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_requests_cpu("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_requests_memory_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_requests_memory("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_requests_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_requests("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_limits_cpu_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_limits_cpu("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 2
}

test_limits_memory_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_limits_memory("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_limits_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_limits("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_with_resources_with_empty_requests_memory_no_violations if {
	inp := {"review": review([ctr_with_resources("test", 1)]), "parameters": {"limits": ["memory"], "requests": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

# "parameters": {"limits": ["cpu"]}
test_without_resources_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_without_resources("test")]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_requests_cpu_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_requests_cpu("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_requests_memory_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_requests_memory("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_requests_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_requests("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_limits_cpu_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_limits_cpu("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_limits_memory_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_limits_memory("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 1
}

test_limits_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_limits("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_with_resources_with_empty_requests_and_limits_memory_no_violations if {
	inp := {"review": review([ctr_with_resources("test", 1)]), "parameters": {"limits": ["cpu"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

# "parameters": {"limits": [], "requests": []}
test_without_resources_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_without_resources("test")]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_requests_cpu_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_requests_cpu("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_requests_memory_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_requests_memory("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_requests_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_requests("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_limits_cpu_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_limits_cpu("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_limits_memory_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_limits_memory("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_limits_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_limits("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_with_resources_with_empty_limits_and_requests_no_violations if {
	inp := {"review": review([ctr_with_resources("test", 1)]), "parameters": {"limits": [], "requests": []}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

# multiple containers, "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}
test_multiple_without_resources_violations if {
	inp := {"review": review([ctr_without_resources("test1"), ctr_without_resources("test2"), ctr_without_resources("test3")]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 6
}

test_multiple_with_resources_no_violations if {
	inp := {"review": review([ctr_with_resources("test1", 1), ctr_with_resources("test2", 2), ctr_with_resources("test3", 3)]), "parameters": {"limits": ["cpu", "memory"], "requests": ["cpu", "memory"]}}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

# multiple containers
test_multiple_with_init_violations_1 if {
	inp := {
		"review": review_with_init(
			[
				ctr_without_resources("test1"),
				ctr_with_resources("test2", 2),
				ctr_limits_memory("test3", 3),
			],
			[
				ctr_requests("test4", 1),
				ctr_requests_memory("test5", 2),
				ctr_limits_cpu("test6", 3),
			],
		),
		"parameters": {"requests": [
			"cpu",
			"memory",
		]},
	}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 4
}

test_multiple_with_init_no_violations if {
	inp := {
		"review": review_with_init(
			[
				ctr_with_resources("test1", 1),
				ctr_requests("test2", 2),
			],
			[
				ctr_with_resources("test3", 1),
				ctr_requests("test4", 2),
			],
		),
		"parameters": {"requests": [
			"cpu",
			"memory",
		]},
	}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 0
}

test_multiple_with_init_violations_2 if {
	inp := {
		"review": review_with_init(
			[
				ctr_without_resources("test1"),
				ctr_limits_memory("test2", 2),
				ctr_limits("test3", 3),
			],
			[
				ctr_requests_cpu("test4", 1),
				ctr_with_resources("test5", 2),
				ctr_limits_cpu("test6", 3),
			],
		),
		"parameters": {
			"limits": ["memory"],
			"requests": [
				"cpu",
				"memory",
			],
		},
	}
	results := violation with input as inp
	trace(sprintf("results - <%v>", [results]))
	count(results) == 8
}

review(containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": containers},
}}

review_with_init(containers, init_containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": containers, "initContainers": init_containers},
}}

ctr_without_resources(name) := {"name": name, "image": "nginx", "resources": {}}

ctr_requests_cpu(name, val) := {"name": name, "image": "nginx", "resources": {"requests": {"cpu": val}}}

ctr_requests_memory(name, val) := {"name": name, "image": "nginx", "resources": {"requests": {"memory": val}}}

ctr_requests(name, val) := {"name": name, "image": "nginx", "resources": {"requests": {"cpu": val, "memory": val}}}

ctr_limits_cpu(name, val) := {"name": name, "image": "nginx", "resources": {"limits": {"cpu": val}}}

ctr_limits_memory(name, val) := {"name": name, "image": "nginx", "resources": {"limits": {"memory": val}}}

ctr_limits(name, val) := {"name": name, "image": "nginx", "resources": {"limits": {"cpu": val, "memory": val}}}

ctr_with_resources(name, val) := {"name": name, "image": "nginx", "resources": {
	"limits": {"cpu": val, "memory": val},
	"requests": {"cpu": val, "memory": val},
}}
