package k8scontainerratios

test_input_no_violations_int {
    inp := {"review": review([ctr("a", 10, 20, 5, 10)]), "parameters": {"ratio": 2}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}
test_input_no_violations_str {
    inp := {"review": review([ctr("a", "10", "20", "5", "10")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}
test_input_no_violations_str_small {
    inp := {"review": review([ctr("a", "1", "2", "1", "1")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}
test_input_no_violations_cpu_scale {
    inp := {"review": review([ctr("a", "2", "4m", "1", "2m")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}
test_input_no_violations_cpu_decimal {
    inp := {"review": review([ctr("a", "2", "3", "1", "1.5")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}
test_input_violations_int {
    inp := {"review": review([ctr("a", 20, 40, 5, 10)]), "parameters": {"ratio": 2}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 2
}
test_input_violations_mem_int_v_str {
    inp := {"review": review([ctr("a", 1, "3", "1m", "1.5")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 1
}
test_input_violations_str {
    inp := {"review": review([ctr("a", "10", "20", "2", "4")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 2
}
test_input_violations_str_small {
    inp := {"review": review([ctr("a", "5", "6", "1", "1")]), "parameters": {"ratio": "3"}}
    results := violation with input as inp
    count(results) == 2
}
test_input_violations_cpu_scale {
    inp := {"review": review([ctr("a", "1", "2", "1", "4m")]), "parameters": {"ratio": "10"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_cpu_decimal {
    inp := {"review": review([ctr("a", "1", "2", "1", "0.5")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 1
}
test_no_parse_cpu_limits {
    inp := {"review": review([ctr("a", "1", "212asdf", "2", "2")]), "parameters": {"raio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_parse_cpu_requests {
    inp := {"review": review([ctr("a", "1", "2", "2", "212asdf")]), "parameters": {"raio": "4"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 1
}
test_no_parse_cpu_requests_and_limits {
    inp := {"review": review([ctr("a", "1", "212asdf", "2", "212asdf")]), "parameters": {"raio": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_parse_ram_limits {
    inp := {"review": review([ctr("a", "1asdf", "2", "1", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_parse_ram_requests {
    inp := {"review": review([ctr("a", "1", "2", "1asdf", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_no_parse_ram_requests_and_limits {
    inp := {"review": review([ctr("a", "1asdf", "2", "1asdf", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_1_bad_cpu {
    inp := {"review": review([ctr("a", "1", "2", "1", "2"), ctr("b", "1", "8", "1", "2")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    count(results) == 1
}
test_2_bad_cpu {
    inp := {"review": review([ctr("a", "1", "9", "1", "3"), ctr("b", "1", "8", "1", "2")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    count(results) == 2
}
test_1_bad_ram {
    inp := {"review": review([ctr("a", "1", "2", "1" ,"2"), ctr("b", "8", "2", "2", "2")]), "parameters": {"ratio": "1"}}
    results := violation with input as inp
    count(results) == 1
}
test_2_bad_ram {
    inp := {"review": review([ctr("a", "9", "2", "3", "2"), ctr("b", "8", "2", "2", "2")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_ram_limit {
    inp := {"review": review([{"name": "a", "resources": {"limits": {"cpu": 1}}}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 2
}
test_no_cpu_limit {
    inp := {"review": review([{"name": "a", "resources": {"limits": {"memory": 1}}}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_limit {
    inp := {"review": review([{"name": "a", "resources": {}}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_ram_request {
    inp := {"review": review([{"name": "a", "resources": {"requests": {"cpu": 1}}}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 2
}
test_no_cpu_request {
    inp := {"review": review([{"name": "a", "resources": {"requests": {"memory": 1}}}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 2
}
test_no_resources {
    inp := {"review": review([{"name": "a"}]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 2
}
test_init_containers_checked {
    inp := {"review": init_review([ctr("a", "5", "5", "1", "1"), ctr("b", "5", "5", "1", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 4
}
# MEM SCALE TESTS
test_input_no_violations_mem_K {
    inp := {"review": review([ctr("a", "1k", "2", "1k", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 0
}
test_input_violations_mem_K {
    inp := {"review": review([ctr("a", "4k", "2", "1k", "2")]), "parameters": {"ratio": "2"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_m {
    inp := {"review": review([ctr("a", "1", "2", "1m", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_M {
    inp := {"review": review([ctr("a", "1M", "2", "1k", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_G {
    inp := {"review": review([ctr("a", "1G", "2", "1M", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_T {
    inp := {"review": review([ctr("a", "1T", "2", "1G", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_P {
    inp := {"review": review([ctr("a", "1P", "2", "1T", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_E {
    inp := {"review": review([ctr("a", "1E", "2", "1P", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ki {
    inp := {"review": review([ctr("a", "1Ki", "2", "1", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Mi {
    inp := {"review": review([ctr("a", "1Mi", "2", "1Ki", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Gi {
    inp := {"review": review([ctr("a", "1Gi", "2", "1Mi", "2")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ti {
    inp := {"review": review([ctr("a", "1Ti", "2", "1Gi", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Pi {
    inp := {"review": review([ctr("a", "1Pi", "2", "1Ti", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ei {
    inp := {"review": review([ctr("a", "1Ei", "2", "1Pi", "1")]), "parameters": {"ratio": "4"}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_mem_Ei_with_exemption {
    inp := {"review": review([ctr("a", "1Ei", "2", "1Pi", "1")]), "parameters": {"exemptImages": ["nginx"], "ratio": "4"}}
    results := violation with input as inp
    count(results) == 0
}

## cpuRatio tests

test_input_no_violations_int_cpu_ratio_1 {
    inp := {"review": review([ctr("a", 5, 10, 5, 10)]), "parameters": {"ratio": 1, "cpuRatio": 1}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}

test_input_violations_int_cpu_ratio_1 {
    inp := {"review": review([ctr("a", 30, 15, 5, 10)]), "parameters": {"ratio": 10, "cpuRatio": 1}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 1
}


test_input_no_violation_int_cpu_ratio_2 {
    inp := {"review": review([ctr("a", 5, 20, 5, 10)]), "parameters": {"ratio": 1, "cpuRatio": 2}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 0
}


test_input_violation_int_cpu_ratio_2 {
    inp := {"review": review([ctr("a", 5, 21, 5, 10)]), "parameters": {"ratio": 1, "cpuRatio": 2}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
    count(results) == 1
}
test_input_violation_int_cpu_ratio_2_with_exemption {
    inp := {"review": review([ctr("a", 5, 21, 5, 10)]), "parameters": {"exemptImages": ["nginx"], "ratio": 1, "cpuRatio": 2}}
    results := violation with input as inp
    trace(sprintf("results - <%v>", [results]))
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

ctr(name, mem_limits, cpu_limits, mem_requests, cpu_requests) = out {
  out = {"name": name, "image": "nginx", "resources": {"limits": {"memory": mem_limits, "cpu": cpu_limits},"requests": {"memory": mem_requests, "cpu": cpu_requests}}}
}
