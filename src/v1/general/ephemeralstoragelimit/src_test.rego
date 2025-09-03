package k8scontainerephemeralstoragelimit

import rego.v1

test_input_no_violations_int if {
	inp := {"review": review([ctr("a", 4096)]), "parameters": {"ephemeral-storage": "8192"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_str if {
	inp := {"review": review([ctr("a", "1Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_str_small if {
	inp := {"review": review([ctr("a", "100")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_violations_int if {
	inp := {"review": review([ctr("a", 4096)]), "parameters": {"ephemeral-storage": "2048"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_str if {
	inp := {"review": review([ctr("a", "2.5Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_str_small if {
	inp := {"review": review([ctr("a", "130")]), "parameters": {"ephemeral-storage": 128}}
	results := violation with input as inp
	count(results) == 1
}

test_no_parse_ephemeral_storage if {
	inp := {"review": review([ctr("a", "123def")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_1_bad_eph if {
	inp := {"review": review([ctr("a", "1Gi"), ctr("a", "3Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_2_bad_eph if {
	inp := {"review": review([ctr("a", "2.5Gi"), ctr("a", "3Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 2
}

test_no_eph_limit if {
	inp := {"review": review([{"name": "a", "resources": {"limits": {"cpu": 1}}}]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_limit if {
	inp := {"review": review([{"name": "a", "resources": {}}]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_no_resources if {
	inp := {"review": review([{"name": "a"}]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_init_containers_checked if {
	inp := {"review": init_review([ctr("a", "2.2 Ti")]), "parameters": {"ephemeral-storage": "3Gi"}}
	results := violation with input as inp
	count(results) == 1
}

# # EPH SCALE TESTS
test_input_no_violations_eph_k if {
	inp := {"review": review([ctr("a", "100k")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 0
}

test_input_violations_eph_m if {
	inp := {"review": review([ctr("a", "10000m")]), "parameters": {"ephemeral-storage": "9"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_K if {
	inp := {"review": review([ctr("a", "1k")]), "parameters": {"ephemeral-storage": "999"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_M if {
	inp := {"review": review([ctr("a", "1M")]), "parameters": {"ephemeral-storage": 999999}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_G if {
	inp := {"review": review([ctr("a", "1G")]), "parameters": {"ephemeral-storage": "999999999"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_T if {
	inp := {"review": review([ctr("a", "1T")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_P if {
	inp := {"review": review([ctr("a", "1P")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_E if {
	inp := {"review": review([ctr("a", "1E")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Ki if {
	inp := {"review": review([ctr("a", "1Ki")]), "parameters": {"ephemeral-storage": "1023"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Mi if {
	inp := {"review": review([ctr("a", "1Mi")]), "parameters": {"ephemeral-storage": "0.5Mi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Gi if {
	inp := {"review": review([ctr("a", "1Gi")]), "parameters": {"ephemeral-storage": "0.22Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_decimal_eph_Gi if {
	inp := {"review": review([ctr("a", "1.4Gi")]), "parameters": {"ephemeral-storage": "1Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Ti if {
	inp := {"review": review([ctr("a", "1Ti")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Pi if {
	inp := {"review": review([ctr("a", "1Pi")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Ei if {
	inp := {"review": review([ctr("a", "1Ei")]), "parameters": {"ephemeral-storage": "2Gi"}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_eph_Ei_with_exemption if {
	inp := {"review": review([ctr("a", "1Ei")]), "parameters": {"exemptImages": ["nginx"], "ephemeral-storage": "1Pi"}}
	results := violation with input as inp
	count(results) == 0
}

test_update if {
	inp := {"review": object.union(review([ctr("a", 4096)]), {"operation": "UPDATE"}), "parameters": {"ephemeral-storage": "2048"}}
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

ctr(name, eph_sto) := {"name": name, "image": "nginx", "resources": {"limits": {"ephemeral-storage": eph_sto}}}
