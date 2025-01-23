package k8scontainerlimits

import rego.v1

test_input_no_violations_int if {
	inp := {"review": review([ctr("a", 10, 20)]), "parameters": {"memory": 20, "cpu": 40}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_str if {
	inp := {"review": review([ctr("a", "10", "20")]), "parameters": {"memory": "20", "cpu": "40"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_str_small if {
	inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_cpu_scale if {
	inp := {"review": review([ctr("a", "1", "2m")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_violations_int if {
	inp := {"review": review([ctr("a", 10, 20)]), "parameters": {"memory": 5, "cpu": 10}}
	results := violation with input as inp
	count(results) == 2
}

test_input_violations_mem_int_v_str if {
	inp := {"review": review([ctr("a", 10, "4")]), "parameters": {"memory": "1000m", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_str if {
	inp := {"review": review([ctr("a", "10", "20")]), "parameters": {"memory": "5", "cpu": "10"}}
	results := violation with input as inp
	count(results) == 2
}

test_input_violations_str_small if {
	inp := {"review": review([ctr("a", "5", "6")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 2
}

test_input_violations_cpu_scale if {
	inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "2", "cpu": "4m"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_parse_cpu if {
	inp := {"review": review([ctr("a", "1", "212asdf")]), "parameters": {"memory": "2", "cpu": "4m"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_parse_cpu_skip if {
	inp := {"review": review([ctr("a", "1", "212asdf")]), "parameters": {"memory": "2", "cpu": "-1"}}
	results := violation with input as inp
	count(results) == 0
}

test_no_parse_ram if {
	inp := {"review": review([ctr("a", "1asdf", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_1_bad_cpu if {
	inp := {"review": review([ctr("a", "1", "2"), ctr("b", "1", "8")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_2_bad_cpu if {
	inp := {"review": review([ctr("a", "1", "9"), ctr("b", "1", "8")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 2
}

test_1_bad_ram if {
	inp := {"review": review([ctr("a", "1", "2"), ctr("b", "8", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_2_bad_ram if {
	inp := {"review": review([ctr("a", "9", "2"), ctr("b", "8", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 2
}

test_no_ram_limit if {
	inp := {"review": review([{"name": "a", "resources": {"limits": {"cpu": 1}}}]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_cpu_limit if {
	inp := {"review": review([{"name": "a", "resources": {"limits": {"memory": 1}}}]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_limit if {
	inp := {"review": review([{"name": "a", "resources": {}}]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_resources if {
	inp := {"review": review([{"name": "a"}]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_init_containers_checked if {
	inp := {"review": init_review([ctr("a", "5", "5"), ctr("b", "5", "5")]), "parameters": {"memory": "2", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 4
}

# MEM SCALE TESTS
test_input_no_violations_mem_K if {
	inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "1k", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_violations_mem_m if {
	inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "1m", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_K if {
	inp := {"review": review([ctr("a", "1k", "2")]), "parameters": {"memory": "1", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_M if {
	inp := {"review": review([ctr("a", "1M", "2")]), "parameters": {"memory": "1k", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_G if {
	inp := {"review": review([ctr("a", "1G", "2")]), "parameters": {"memory": "1M", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_T if {
	inp := {"review": review([ctr("a", "1T", "2")]), "parameters": {"memory": "1G", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_P if {
	inp := {"review": review([ctr("a", "1P", "2")]), "parameters": {"memory": "1T", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_E if {
	inp := {"review": review([ctr("a", "1E", "2")]), "parameters": {"memory": "1P", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Ki if {
	inp := {"review": review([ctr("a", "1Ki", "2")]), "parameters": {"memory": "1", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Mi if {
	inp := {"review": review([ctr("a", "1Mi", "2")]), "parameters": {"memory": "1Ki", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Gi if {
	inp := {"review": review([ctr("a", "1Gi", "2")]), "parameters": {"memory": "1Mi", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_decimal_mem_Gi if {
	inp := {"review": review([ctr("a", "1Gi", "2")]), "parameters": {"memory": "1.5Mi", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Ti if {
	inp := {"review": review([ctr("a", "1Ti", "2")]), "parameters": {"memory": "1Gi", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Pi if {
	inp := {"review": review([ctr("a", "1Pi", "2")]), "parameters": {"memory": "1Ti", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Ei if {
	inp := {"review": review([ctr("a", "1Ei", "2")]), "parameters": {"memory": "1Pi", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_mem_Ei_with_exemption if {
	inp := {"review": review([ctr("a", "1Ei", "2")]), "parameters": {"exemptImages": ["nginx"], "memory": "1Pi", "cpu": "4"}}
	results := violation with input as inp
	count(results) == 0
}

review(containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"containers": containers},
}}

init_review(containers) := {"object": {
	"metadata": {"name": "nginx"},
	"spec": {"initContainers": containers},
}}

ctr(name, mem, cpu) := {
	"name": name,
	"image": "nginx",
	"resources": {"limits": {"memory": mem, "cpu": cpu}},
}
