package k8srequirednodeselectors

test_no_required_node_selectors {
    input := { "review": review({}), "parameters" : {}}
    results := violation with input as input
    count(results) == 0
}

test_no_required_node_selectors {
    input := { "review": review({"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux"}), "parameters" : {}}
    results := violation with input as input
    count(results) == 0
}

test_has_required_node_selectors {
    input := { "review": review({"kubernetes.io/os": "windows"}), "parameters": {"nodeSelectors": ["kubernetes.io/os"]}}
    results := violation with input as input
    count(results) == 0
}

test_has_requried_node_selectors {
    input := { "review": review({"1": "a", "2": "b", "3": "c"}), "parameters": {"nodeSelectors": ["1", "2", "3"]}}
    results := violation with input as input
    count(results) == 0
}

test_missing_required_node_selectors {
    input := { "review": review({}), "parameters": {"nodeSelectors": ["kubernetes.io/os"]}}
    results := violation with input as input
    count(results) == 1
}

test_some_requried_node_selectors {
    input := { "review": review({"1": "a"}), "parameters": {"nodeSelectors": ["1", "2", "3"]}}
    results := violation with input as input
    count(results) == 1
}

review(nodeSelectors) = out {
    out = {
        "object": {
            "kind": "Pod",
            "spec" : {
                "nodeSelector": nodeSelectors
            }
        }
    }
}
