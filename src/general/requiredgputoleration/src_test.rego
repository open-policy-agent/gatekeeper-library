package k8srequiredgputoleration

test_gpu_with_toleration_allowed {
    inp := {"review": review_with_tolerations([gpu_container("train", "nvidia/cuda:12.0", "1")], [{"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}]), "parameters": {"tolerationKey": "nvidia.com/gpu"}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_without_toleration_denied {
    inp := {"review": review([gpu_container("train", "nvidia/cuda:12.0", "1")]), "parameters": {"tolerationKey": "nvidia.com/gpu"}}
    results := violation with input as inp
    count(results) == 1
}

test_no_gpu_allowed {
    inp := {"review": review([no_gpu_container("web", "nginx:latest")]), "parameters": {"tolerationKey": "nvidia.com/gpu"}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_wrong_toleration_denied {
    inp := {"review": review_with_tolerations([gpu_container("train", "nvidia/cuda:12.0", "1")], [{"key": "other-key", "operator": "Exists", "effect": "NoSchedule"}]), "parameters": {"tolerationKey": "nvidia.com/gpu"}}
    results := violation with input as inp
    count(results) == 1
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

review_with_tolerations(containers, tolerations) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "tolerations": tolerations}}}
}

gpu_container(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}}
}

no_gpu_container(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"cpu": "100m"}}}
}
