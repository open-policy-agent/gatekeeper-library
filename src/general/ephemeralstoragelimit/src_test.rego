package k8scontainerephemeralstoragelimit

test_input_no_violations_int {
    input := {"review": review([ctr("a", 4096)]), "parameters": {"ephemeral-storage": "8192"}}
    results := violation with input as input
    count(results) == 0
}
test_input_no_violations_str {
    input := {"review": review([ctr("a", "1Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 0
}
test_input_no_violations_str_small {
    input := {"review": review([ctr("a", "100")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 0
}
test_input_violations_int {
    input := {"review": review([ctr("a", 4096)]), "parameters": {"ephemeral-storage": "2048"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_str {
    input := {"review": review([ctr("a", "2.5Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_str_small {
    input := {"review": review([ctr("a", "130")]), "parameters": {"ephemeral-storage": 128}}
    results := violation with input as input
    count(results) == 1
}
test_no_parse_ephemeral_storage {
    input := {"review": review([ctr("a", "123def")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_1_bad_eph {
    input := {"review": review([ctr("a", "1Gi"), ctr("a", "3Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_2_bad_eph {
    input := {"review": review([ctr("a", "2.5Gi"), ctr("a", "3Gi")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 2
}
test_no_eph_limit {
    input := {"review": review([{"name": "a", "resources": {"limits": {"cpu": 1}}}]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_no_limit {
    input := {"review": review([{"name": "a", "resources": {}}]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_no_resources {
    input := {"review": review([{"name": "a"}]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_init_containers_checked {
    input := {"review": init_review([ctr("a", "2.2 Ti")]), "parameters": {"ephemeral-storage": "3Gi"}}
    results := violation with input as input
    count(results) == 1
}

# # EPH SCALE TESTS
test_input_no_violations_eph_k {
    input := {"review": review([ctr("a", "100k")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 0
}
test_input_violations_eph_m {
    input := {"review": review([ctr("a", "10000m")]), "parameters": {"ephemeral-storage": "9"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_K {
    input := {"review": review([ctr("a", "1k")]), "parameters": {"ephemeral-storage": "999"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_M {
    input := {"review": review([ctr("a", "1M")]), "parameters": {"ephemeral-storage": 999999}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_G {
    input := {"review": review([ctr("a", "1G")]), "parameters": {"ephemeral-storage": "999999999"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_T {
    input := {"review": review([ctr("a", "1T")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_P {
    input := {"review": review([ctr("a", "1P")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_E {
    input := {"review": review([ctr("a", "1E")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Ki {
    input := {"review": review([ctr("a", "1Ki")]), "parameters": {"ephemeral-storage": "1023"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Mi {
    input := {"review": review([ctr("a", "1Mi")]), "parameters": {"ephemeral-storage": "0.5Mi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Gi {
    input := {"review": review([ctr("a", "1Gi")]), "parameters": {"ephemeral-storage": "0.22Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_decimal_eph_Gi {
    input := {"review": review([ctr("a", "1.4Gi")]), "parameters": {"ephemeral-storage": "1Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Ti {
    input := {"review": review([ctr("a", "1Ti")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Pi {
    input := {"review": review([ctr("a", "1Pi")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Ei {
    input := {"review": review([ctr("a", "1Ei")]), "parameters": {"ephemeral-storage": "2Gi"}}
    results := violation with input as input
    count(results) == 1
}
test_input_violations_eph_Ei_with_exemption {
    input := {"review": review([ctr("a", "1Ei")]), "parameters": {"exemptImages": ["nginx"], "ephemeral-storage": "1Pi"}}
    results := violation with input as input
    count(results) == 0
}
test_update {
    input := {"review": object.union(review([ctr("a", 4096)]), {"operation": "UPDATE"}), "parameters": {"ephemeral-storage": "2048"}}
    results := violation with input as input
    count(results) == 0
}

review(containers) = output {
  output = {
    "object": {
      "metadata": {
        "name": "nginx",
      },
      "spec": {"containers": containers}
    }
  }
}

init_review(containers) = output {
  output = {
    "object": {
      "metadata": {
        "name": "nginx",
      },
      "spec": {"initContainers": containers}
    }
  }
}

ctr(name, eph_sto) = out {
  out = {"name": name, "image": "nginx", "resources": {"limits": {"ephemeral-storage": eph_sto}}}
}
