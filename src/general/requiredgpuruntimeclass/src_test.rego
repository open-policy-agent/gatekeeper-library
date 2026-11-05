package k8srequiredgpuruntimeclass

test_gpu_with_runtime_class_allowed {
    inp := {"review": review_with_rc([gpu_container("train", "nvidia/cuda:12.0", "1")], "nvidia"), "parameters": {"allowedRuntimeClassNames": ["nvidia"]}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_without_runtime_class_denied {
    inp := {"review": review([gpu_container("train", "nvidia/cuda:12.0", "1")]), "parameters": {"allowedRuntimeClassNames": ["nvidia"]}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_wrong_runtime_class_denied {
    inp := {"review": review_with_rc([gpu_container("train", "nvidia/cuda:12.0", "1")], "runc"), "parameters": {"allowedRuntimeClassNames": ["nvidia"]}}
    results := violation with input as inp
    count(results) == 1
}

test_no_gpu_allowed {
    inp := {"review": review([no_gpu_container("web", "nginx:latest")]), "parameters": {"allowedRuntimeClassNames": ["nvidia"]}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

review_with_rc(containers, rc) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "runtimeClassName": rc}}}
}

gpu_container(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}}
}

no_gpu_container(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"cpu": "100m"}}}
}
