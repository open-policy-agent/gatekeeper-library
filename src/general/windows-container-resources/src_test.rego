package k8swindowscontainerresources

test_input_no_resources_no_node_selector {
    input := {"review": review([ctr("ctr1", null, null)], null, null)}
    results := violation with input as input
    count(results) == 0
}

test_input_no_resources {
    input := {"review": review([ctr("ctr1", null, null)], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_input_no_cpu_limit {
    input := {"review": review([ctr("ctr1", limits(null, "500m"), null)], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_input_no_mem_limit {
    input := {"review": review([ctr("ctr1", limits(0.5, null), null)], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_input_with_limits {
    input := {"review": review([ctr("ctr1", limits(0.5, "500m"), null)],null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 0
}

test_input_no_limits_with_requests {
    input := {"review": review([ctr("ctr1", null, requests(0.5, "500m"))], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_input_limits_match_requests {
    input := {"review": review([ctr("ctr1", limits(0.5, "500m"), requests(0.5, "500m"))], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 0
}

test_input_limits_do_not_match_requests1 {
    input := {"review": review([ctr("ctr1", limits(0.5, "500m"), requests(0.25, "500m"))], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_input_limits_do_not_match_requests2 {
    input := {"review": review([ctr("ctr1", limits(0.5, "500m"), requests(0.5, "250m"))], null, windowsNodeSelector)}
    results := violation with input as input
    count(results) == 1
}

test_multiple_containers {
    input := {"review": review(
        [
            ctr("ctr1", null, null),                                    # bad
            ctr("ctr2", limits(0.5, "500m"), null),                      # good
            ctr("ctr3", null, requests(0.5, "500m"))                     # bad
        ],[ 
            ctr("init_1", null, null),                                  # bad
            ctr("init_2", limits(0.5, "500m"), requests(0.25, "250m")),   # bad
            ctr("init_3", limits(0.5, "500m"), requests(0.5, "500m")),    # good
            ctr("init_4", limits(0.5, "500m"), null)                     # good
        ], windowsNodeSelector)}
    results := violation with input as input
    count(results) == 4
}

review(containers, init_containers, node_selector) = out {
    containers_obj := obj_if_exists("containers", containers)
    init_containers_obj := obj_if_exists("initContainers", init_containers)
    node_selector_obj := obj_if_exists("nodeSelector", node_selector)
    out = {
        "object": {
            "spec": object.union(object.union(containers_obj, init_containers_obj), node_selector_obj)
        }
    }
}

windowsNodeSelector = out {
    out = {
        "kubernetes.io/os": "windows"
    }
}

ctr(name, limits, requests) = out {
    out = {
        "name": name,
        "resources": object.union(obj_if_exists("limits", limits), obj_if_exists("requests", requests))
    }
}

limits(cpu, mem) = out {
    out =  object.union(obj_if_exists("cpu", cpu), obj_if_exists("memory", mem))
}

requests(cpu, mem) = out {
    out = object.union(obj_if_exists("cpu", cpu), obj_if_exists("memory", mem))
}

obj_if_exists(key, val) = out {
    not is_null(val)
    out := {key: val}
}
obj_if_exists(key, val) = out {
    is_null(val)
    out := {}
}