package k8sgpuactivedeadline

test_gpu_with_deadline_allowed {
    inp := {"review": review_with_deadline([gpu_container("train", "nvidia/cuda:12.0", "1")], 3600), "parameters": {"maxActiveDeadlineSeconds": 86400}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_without_deadline_denied {
    inp := {"review": review([gpu_container("train", "nvidia/cuda:12.0", "1")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_exceeds_max_deadline_denied {
    inp := {"review": review_with_deadline([gpu_container("train", "nvidia/cuda:12.0", "1")], 172800), "parameters": {"maxActiveDeadlineSeconds": 86400}}
    results := violation with input as inp
    count(results) == 1
}

test_no_gpu_allowed {
    inp := {"review": review([no_gpu_container("web", "nginx:latest")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

review_with_deadline(containers, deadline) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "activeDeadlineSeconds": deadline}}}
}

gpu_container(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}}
}

no_gpu_container(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"cpu": "100m"}}}
}
