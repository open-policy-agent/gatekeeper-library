package k8scontainerrequests

test_input_no_violations_int {
    inp := {"review": review([ctr("a", 10, 20)]), "parameters": {"memory": 20, "cpu": 40}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_str {
    inp := {"review": review([ctr("a", "10", "20")]), "parameters": {"memory": "20", "cpu": "40"}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_str_small {
    inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_cpu_scale {
    inp := {"review": review([ctr("a", "1", "2m")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 0
}
test_input_violations_int {
    inp := {"review": review([ctr("a", 10, 20)]), "parameters": {"memory": 5, "cpu": 10}}
    results := violation with input as inp
    count(results) == 2
}

test_input_violations_mem_int_v_str {
    inp := {"review": review([ctr("a", 10, "4")]), "parameters": {"memory": "1000m", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}

test_input_violations_str {
    inp := {"review": review([ctr("a", "10", "20")]), "parameters": {"memory": "5", "cpu": "10"}}
    results := violation with input as inp
    count(results) == 2
}
test_input_violations_str_small {
    inp := {"review": review([ctr("a", "5", "6")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_input_violations_cpu_scale {
    inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "2", "cpu": "4m"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_parse_cpu {
    inp := {"review": review([ctr("a", "1", "212asdf")]), "parameters": {"memory": "2", "cpu": "4m"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_parse_ram {
    inp := {"review": review([ctr("a", "1asdf", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_1_bad_cpu {
    inp := {"review": review([ctr("a", "1", "2"), ctr("b", "1", "8")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_2_bad_cpu {
    inp := {"review": review([ctr("a", "1", "9"), ctr("b", "1", "8")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_1_bad_ram {
    inp := {"review": review([ctr("a", "1", "2"), ctr("b", "8", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_2_bad_ram {
    inp := {"review": review([ctr("a", "9", "2"), ctr("b", "8", "2")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_ram_request {
    inp := {"review": review([{"name": "a", "resources": {"requests": {"cpu": 1}}}]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_cpu_request {
    inp := {"review": review([{"name": "a", "resources": {"requests": {"memory": 1}}}]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_request {
    inp := {"review": review([{"name": "a", "resources": {}}]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_resources {
    inp := {"review": review([{"name": "a"}]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_init_containers_checked {
    inp := {"review": init_review([ctr("a", "5", "5"), ctr("b", "5", "5")]), "parameters": {"memory": "2", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 4
}

# MEM SCALE TESTS
test_input_no_violations_mem_K {
    inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "1k", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 0
}
test_input_violations_mem_m {
    inp := {"review": review([ctr("a", "1", "2")]), "parameters": {"memory": "1m", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_K {
    inp := {"review": review([ctr("a", "1k", "2")]), "parameters": {"memory": "1", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_M {
    inp := {"review": review([ctr("a", "1M", "2")]), "parameters": {"memory": "1k", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_G {
    inp := {"review": review([ctr("a", "1G", "2")]), "parameters": {"memory": "1M", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_T {
    inp := {"review": review([ctr("a", "1T", "2")]), "parameters": {"memory": "1G", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_P {
    inp := {"review": review([ctr("a", "1P", "2")]), "parameters": {"memory": "1T", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_E {
    inp := {"review": review([ctr("a", "1E", "2")]), "parameters": {"memory": "1P", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ki {
    inp := {"review": review([ctr("a", "1Ki", "2")]), "parameters": {"memory": "1", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Mi {
    inp := {"review": review([ctr("a", "1Mi", "2")]), "parameters": {"memory": "1Ki", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Gi {
    inp := {"review": review([ctr("a", "1Gi", "2")]), "parameters": {"memory": "1Mi", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_decimal_mem_Gi {
    inp := {"review": review([ctr("a", "1Gi", "2")]), "parameters": {"memory": "1.5Mi", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ti {
    inp := {"review": review([ctr("a", "1Ti", "2")]), "parameters": {"memory": "1Gi", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Pi {
    inp := {"review": review([ctr("a", "1Pi", "2")]), "parameters": {"memory": "1Ti", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ei {
    inp := {"review": review([ctr("a", "1Ei", "2")]), "parameters": {"memory": "1Pi", "cpu": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ei_with_exemption {
    inp := {"review": review([ctr("a", "1Ei", "2")]), "parameters": {"exemptImages": ["nginx"], "memory": "1Pi", "cpu": "4"}}
    results := violation with input as inp
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

ctr(name, mem, cpu) = out {
  out = {"name": name, "image": "nginx", "resources": {"requests": {"memory": mem, "cpu": cpu}}}
}
