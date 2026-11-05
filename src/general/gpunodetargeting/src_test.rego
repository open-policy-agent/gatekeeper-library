package k8sgpunodetargeting

test_gpu_pod_with_node_affinity_allowed {
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_gpu_affinity("nvidia.com/gpu.present", ["true"])), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_with_node_selector_allowed {
    inp := {"review": review_with_node_selector([gpu_container("trainer")], {"nvidia.com/gpu.present": "true"}), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_node_selector_key_only_allowed {
    inp := {"review": review_with_node_selector([gpu_container("trainer")], {"nvidia.com/gpu.present": "true"}), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present"}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_node_selector_key_only_empty_value_denied {
    inp := {"review": review_with_node_selector([gpu_container("trainer")], {"nvidia.com/gpu.present": ""}), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present"}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_without_targeting_denied {
    inp := {"review": review([gpu_container("trainer")]), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_wrong_node_label_value_denied {
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_gpu_affinity("nvidia.com/gpu.present", ["false"])), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_mixed_node_label_values_denied {
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_gpu_affinity("nvidia.com/gpu.present", ["true", "false"])), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_with_mixed_affinity_terms_denied {
    terms := [
        {"matchExpressions": [{"key": "nvidia.com/gpu.present", "operator": "In", "values": ["true"]}]},
        {"matchExpressions": [{"key": "kubernetes.io/os", "operator": "In", "values": ["linux"]}]},
    ]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_with_all_matching_affinity_terms_allowed {
    terms := [
        {"matchExpressions": [{"key": "nvidia.com/gpu.present", "operator": "In", "values": ["true"]}]},
        {"matchExpressions": [{"key": "nvidia.com/gpu.present", "operator": "In", "values": ["true"]}, {"key": "kubernetes.io/os", "operator": "In", "values": ["linux"]}]},
    ]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_node_affinity_key_only_exists_allowed {
    terms := [{"matchExpressions": [{"key": "nvidia.com/gpu.product", "operator": "Exists"}]}]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.product"}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_node_affinity_key_only_in_allowed {
    terms := [{"matchExpressions": [{"key": "nvidia.com/gpu.product", "operator": "In", "values": ["A100"]}]}]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.product"}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_pod_node_affinity_key_only_in_empty_denied {
    terms := [{"matchExpressions": [{"key": "nvidia.com/gpu.product", "operator": "In", "values": []}]}]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.product"}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_node_affinity_key_only_not_in_denied {
    terms := [{"matchExpressions": [{"key": "nvidia.com/gpu.product", "operator": "NotIn", "values": ["A100"]}]}]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.product"}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_node_affinity_key_only_does_not_exist_denied {
    terms := [{"matchExpressions": [{"key": "nvidia.com/gpu.product", "operator": "DoesNotExist"}]}]
    inp := {"review": review_with_affinity([gpu_container("trainer")], required_affinity(terms)), "parameters": {"nodeLabelKey": "nvidia.com/gpu.product"}}
    results := violation with input as inp
    count(results) == 1
}

test_non_gpu_pod_allowed {
    inp := {"review": review([non_gpu_container("web")]), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"]}}
    results := violation with input as inp
    count(results) == 0
}

test_exempt_gpu_container_allowed {
    inp := {"review": review([gpu_container_with_image("monitor", "nvidia/dcgm-exporter:3.1")]), "parameters": {"nodeLabelKey": "nvidia.com/gpu.present", "nodeLabelValues": ["true"], "exemptImages": ["nvidia/dcgm-exporter:*"]}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

review_with_affinity(containers, affinity) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "affinity": affinity}}}
}

review_with_node_selector(containers, node_selector) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "nodeSelector": node_selector}}}
}

required_gpu_affinity(key, values) = affinity {
    terms := [
        {"matchExpressions": [{"key": key, "operator": "In", "values": values}]},
    ]
    affinity := required_affinity(terms)
}

required_affinity(terms) = affinity {
    affinity := {
        "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": terms,
            },
        },
    }
}

gpu_container(name) = c {
    c := gpu_container_with_image(name, "nvidia/cuda:12.0-runtime")
}

gpu_container_with_image(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": "1"}}}
}

non_gpu_container(name) = c {
    c := {"name": name, "image": "nginx:1.25", "resources": {"limits": {"cpu": "500m", "memory": "128Mi"}}}
}